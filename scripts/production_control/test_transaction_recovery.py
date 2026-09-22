"""Crash boundaries use BaseException so ordinary rollback cannot hide a lost journal."""
import json
import unittest
from unittest.mock import patch

import restart_production as control
import test_restart_control as fixtures
from watchdog import tick


class PowerLoss(BaseException):
    pass


class TransactionTests(unittest.TestCase):
    setUp = fixtures.ControlTests.setUp
    preflight = fixtures.ControlTests.preflight
    write_gateway = fixtures.ControlTests.write_gateway
    candidate = fixtures.ControlTests.candidate

    def fresh(self):
        return control.Controller(self.base, self.host, self.preflight, self.clock,
                                  self.clock, self.clock.sleep, owner=lambda: 1,
                                  timeout=5, stable_seconds=1)

    def interrupt(self, boundary, reload=False):
        candidate = self.candidate(release_id='candidate')
        write, kick = control.atomic_write, self.host.kickstart
        def crash_write(path, data):
            write(path, data)
            if path == boundary:
                raise PowerLoss()
        def crash_kick(target):
            kick(target)
            if target.rsplit('/', 1)[-1] == boundary:
                raise PowerLoss()
        with patch.object(control, 'atomic_write', side_effect=crash_write), \
             patch.object(self.host, 'kickstart', side_effect=crash_kick):
            with self.assertRaises(PowerLoss):
                self.c.restart(candidate=candidate, reload=reload, yes=True)

    def test_each_cutover_write_and_kick_recovers_exact_pair(self):
        for boundary in ('manifest', 'agent.plist', 'webui.plist', 'agent', 'webui'):
            with self.subTest(boundary=boundary):
                # Every boundary starts from a separate transaction and real disk backup.
                old = self.c.manifest_path.read_bytes()
                saved = {s: p.read_bytes() for s, p in self.plists.items()}
                target = self.c.manifest_path if boundary == 'manifest' else (
                    self.base / boundary if boundary.endswith('.plist') else boundary)
                self.interrupt(target, reload=boundary.endswith('.plist'))
                self.assertEqual(self.c.read_transaction()['authorization'], 'verified-live-fallback')
                self.clock.sleep(86400 * 30)  # Known-good authorization has no TTL.
                self.assertEqual(tick(self.fresh())['status'], 'rolled_back')
                self.assertEqual(self.c.manifest_path.read_bytes(), old)
                self.assertEqual({s: p.read_bytes() for s, p in self.plists.items()}, saved)

    def test_unhealthy_candidate_rejected_but_same_release_restart_allowed(self):
        self.host.deep = False
        with self.assertRaisesRegex(control.ControlError, 'Health JSON'):
            self.c.restart(candidate=self.candidate(), yes=True)
        self.assertEqual(self.host.calls, [])
        self.assertFalse(self.c.transaction_path.exists())
        # A dead service can be repaired by routine restart, without live proof.
        self.host.deep = True
        self.host.jobs['agent']['pid'] = 0
        self.assertEqual(self.c.restart(yes=True)['status'], 'verified')
        self.assertEqual(self.c.read_transaction()['authorization'], 'same-release-restart')

    def test_recovery_obeys_shared_lock(self):
        self.interrupt(self.c.manifest_path)
        with control.control_lock(self.base):
            self.assertEqual(tick(self.fresh())['status'], 'busy')
            with self.assertRaisesRegex(control.ControlError, 'control.lock'):
                self.fresh().restart(yes=True)
        self.assertEqual(self.host.calls, [])
        self.assertEqual(tick(self.fresh())['status'], 'rolled_back')

    def test_revoked_or_malformed_policy_blocks_fallback_without_writes(self):
        policies = [
            {'schema_version': 1, 'release_ids': ['old'], 'content_digests': []},
            {'schema_version': 1, 'release_ids': [],
             'content_digests': [self.c.content_digest(self.manifest)]},
            {'schema_version': 1, 'release_ids': [], 'content_digest': []},
            {'schema_version': 1, 'release_ids': [], 'content_digests': ['bad']},
        ]
        for policy in policies:
            with self.subTest(policy=policy):
                self.setUp()
                self.manifest['release_id'] = 'old'
                control.save_json(self.c.manifest_path, self.manifest)
                # Digest depends on paths, so compute it in the new fixture.
                if policy.get('content_digests') and policy['content_digests'] != ['bad']:
                    policy['content_digests'] = [self.c.content_digest(self.manifest)]
                self.interrupt(self.c.manifest_path)
                current = self.c.manifest_path.read_bytes()
                control.save_json(self.base / 'revoked-releases.json', policy)
                self.assertEqual(tick(self.fresh())['status'], 'rollback_failed')
                self.assertEqual(self.c.manifest_path.read_bytes(), current)
                self.assertEqual(tick(self.fresh())['status'], 'blocked')
                self.assertEqual(self.host.calls, [])

    def test_corrupt_or_unknown_transaction_never_stops(self):
        self.interrupt(self.c.manifest_path)
        original = json.loads(self.c.transaction_path.read_text())
        for field, value in [('schema_version', 99), ('sha256', 'corrupt')]:
            damaged = dict(original, **{field: value})
            control.save_json(self.c.transaction_path, damaged)
            self.assertEqual(tick(self.fresh())['status'], 'blocked')
            with self.assertRaises(control.ControlError):
                self.fresh().restart(yes=True)
            self.assertEqual(self.host.calls, [])

    def test_rollback_crash_is_terminal_before_any_second_attempt(self):
        for boundary in ('manifest', 'agent', 'webui'):
            with self.subTest(boundary=boundary):
                self.setUp()
                self.interrupt(self.c.manifest_path)
                write, kick = control.atomic_write, self.host.kickstart
                def crash_write(path, data):
                    write(path, data)
                    if boundary == 'manifest' and path == self.c.manifest_path:
                        raise PowerLoss()
                def crash_kick(target):
                    kick(target)
                    if target.rsplit('/', 1)[-1] == boundary:
                        raise PowerLoss()
                with patch.object(control, 'atomic_write', side_effect=crash_write), \
                     patch.object(self.host, 'kickstart', side_effect=crash_kick):
                    with self.assertRaises(PowerLoss):
                        tick(self.fresh())
                self.assertEqual(self.c.read_transaction()['phase'], 'rollback_started')
                calls = list(self.host.calls)
                for _ in range(3):
                    self.assertEqual(tick(self.fresh())['status'], 'blocked')
                with self.assertRaisesRegex(control.ControlError, 'rollback_failed'):
                    self.fresh().restart(yes=True)
                self.assertEqual(self.c.read_transaction()['phase'], 'rollback_failed')
                self.assertEqual(self.host.calls, calls)

    def test_failed_rollback_is_terminal_and_finished_backup_never_reused(self):
        self.interrupt(self.c.manifest_path)
        self.host.fail_kicks = {1}
        self.assertEqual(tick(self.fresh())['status'], 'rollback_failed')
        self.assertEqual(tick(self.fresh())['status'], 'blocked')
        self.assertEqual(self.host.kicks, 1)
        for phase in ('verified', 'rolled_back'):
            with self.subTest(phase=phase):
                self.setUp()
                if phase == 'verified':
                    self.c.restart(candidate=self.candidate(release_id='candidate'), yes=True)
                else:
                    self.interrupt(self.c.manifest_path)
                    tick(self.fresh())
                current = self.c.manifest_path.read_bytes()
                calls = list(self.host.calls)
                self.assertEqual(tick(self.fresh(), grace=0)['status'], 'healthy')
                self.assertEqual(self.c.manifest_path.read_bytes(), current)
                self.assertEqual(self.host.calls, calls)

    def test_restart_recovers_without_blessing_requested_candidate(self):
        self.interrupt(self.c.manifest_path)
        result = self.fresh().restart(candidate=self.candidate(release_id='another'), yes=True)
        self.assertEqual(result['status'], 'rolled_back')
        self.assertNotEqual(self.c.load().get('release_id'), 'another')
