"""Actual sealed six-module install -> pending policy; OS/service edges are fixtures.

Run under a nonproduction interpreter, disposable HOME/TMPDIR, no credentials.
No installed maintenance entrypoint, native executable, or release Python runs.
"""
import copy
import importlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import test_upgrade_native_controls_composition as installer_fixture
import upgrade_native_controls as u


class PendingUpgradeCompositionTests(unittest.TestCase):
    def setUp(self):
        f = installer_fixture.NativeUpgradeCompositionTests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        self.addCleanup(f.tearDown)
        self.f = f
        self.base, self.host = f.base, f.f.host
        self.clock = f.f.f.clock
        # Generate a real terminal schema-2 rolled_back transaction through the
        # existing recovery controller, not a hand-written success envelope.
        f.f.test_native_fallback_recovery_remains_schema2_and_one_attempt()
        txn = json.loads(f.f.c.transaction_path.read_bytes())
        self.assertEqual((txn['schema_version'], txn['transaction']['phase']), (2, 'rolled_back'))
        self.old_bytes = f.f.c.manifest_path.read_bytes()
        self.old = json.loads(self.old_bytes)
        self.protected = {p: (p.read_bytes(), p.stat().st_ino, p.stat().st_mode)
                          for p in (*f.f.protected, *f.f.f.plists.values())}
        before_calls = list(self.host.calls)
        plan = u.build_plan(self.base, f.repo, f.commit, 'pending-v3', self.base/'pending-plan', f.f.pin)
        self.assertEqual(self.host.calls, before_calls)
        installed = u.apply_plan(Path(plan['plan']), plan['plan_sha256'], approval=True)
        self.assertEqual(installed['status'], 'installed_controls_no_restart')
        self.assertEqual(self.host.calls, before_calls)
        self.assertEqual(f.f.c.manifest_path.read_bytes(), self.old_bytes)
        self.pin, self.version = installed['new_pin'], Path(installed['version'])
        u.admit(self.base, self.pin, self.version)
        u.verify_bundle(self.version, json.loads((self.version/'control-receipt.json').read_bytes()))
        # Import actual newly installed code, not source watchdog attached to an
        # older Controller. Keep the entire six-module resolution in this bundle.
        modules = patch.dict(sys.modules)
        modules.start()
        self.addCleanup(modules.stop)
        for name in u.FILES:
            sys.modules.pop(name[:-3], None)
        paths = patch.object(sys, 'path', [str(self.version), *sys.path])
        paths.start()
        self.addCleanup(paths.stop)
        self.control = importlib.import_module('restart_production')
        self.w = importlib.import_module('watchdog')
        assert self.w.__file__ is not None and self.control.__file__ is not None
        self.assertEqual(Path(self.w.__file__).parent, self.version)
        self.assertEqual(Path(self.control.__file__).parent, self.version)
        self.installed_records = {name: u.record(self.base/name)
                                  for name in (*u.WRAPPERS, u.RECEIPT, u.JOURNAL)}
        self.addCleanup(self.check_installed_authority)
        self.c = self.control.Controller(self.base, self.host, f.f.old.preflight_fn,
            self.clock, self.clock, self.clock.sleep, owner=lambda: 1,
            timeout=5, stable_seconds=2, control_refresh_sha256=self.pin)
        self.new = copy.deepcopy(self.old)
        self.new['release_id'] = 'pending-composed-candidate'
        for role in ('agent', 'webui'):
            self.new['services'][role]['argv'] = ['/usr/bin/python3', '-B', str(self.base/('candidate-'+role+'.py'))]
            self.new['services'][role]['commit'] = 'candidate-'+role
        self.candidate = self.base/'pending-candidate.json'
        self.control.save_json(self.candidate, self.new)
        # Freeze OS identity independently from the selector so selection cannot
        # accidentally simulate a process restart or alter its loaded argv.
        self.processes = {pid: copy.deepcopy(self.host.process_identity(pid))
                          for job in self.host.jobs.values() for pid in (job['pid'], job['pid']+1)}
        self.host.process_identity = lambda pid: copy.deepcopy(self.processes[pid])
        self.host.calls.clear()

    def check_installed_authority(self):
        self.assertEqual(self.installed_records,
                         {name: u.record(self.base/name) for name in self.installed_records})
        u.admit(self.base, self.pin, self.version)

    def stage_select(self):
        result = self.w.prepare(self.c, self.candidate,
            expected_old_sha256=self.w.digest(self.old_bytes),
            expected_new_sha256=self.w.digest(self.candidate.read_bytes()), timeout=60)
        self.pending_pin = result['receipt_sha256']
        self.assertEqual(self.c.manifest_path.read_bytes(), self.old_bytes)
        self.assertEqual(self.w.tick(self.c, grace=0)['status'], 'healthy')
        self.assertEqual(self.w.select(self.c, self.pending_pin)['status'], 'selected_awaiting_user_restart')
        self.assertEqual(self.host.calls, [])
        self.assertEqual(self.c.read_transaction()['phase'], 'rolled_back')
        self.assertEqual(self.c.read_transaction()['pending_restart_sha256'], self.pending_pin)
        for p, expected in self.protected.items():
            self.assertEqual((p.read_bytes(), p.stat().st_ino, p.stat().st_mode), expected)

    def launch(self, role):
        before = self.host.jobs[role]['pid']
        after = before + 1000
        self.host.jobs[role]['pid'] = after
        for pid in (before, before+1):
            identity = copy.deepcopy(self.processes[pid])
            identity.update(pid=pid+1000, start_time=self.clock())
            if pid == before+1:
                identity.update(ppid=after, argv=self.new['services'][role]['argv'])
            self.processes[pid+1000] = identity
        if role == 'agent':
            self.control.save_json(self.base/'gateway_state.json', dict(pid=after+1,
                gateway_state='running', code_sha=self.new['services'][role]['commit'], updated_at=self.clock()))
        else:
            self.host.started = self.clock()

    def observe(self, **kwargs):
        with self.c.locked():
            return self.w.observe(self.c, self.pending_pin, **kwargs)

    def test_installed_old_mixed_new_stable_and_selector_only_rollback(self):
        self.stage_select()
        old = self.w.tick(self.c, grace=0)
        self.assertEqual((old['status'], old['pending']['status']), ('healthy', 'awaiting_user_restart'))
        self.clock.sleep(1)
        self.launch('webui')
        mixed = self.w.tick(self.c, grace=0)
        self.assertEqual((mixed['status'], mixed['pending']['status']), ('healthy', 'transition'))
        self.assertEqual(mixed['pending']['running'], dict(agent='old', webui='new'))
        self.launch('agent')
        self.assertEqual(self.observe()['status'], 'candidate_observed')
        self.clock.sleep(1)
        self.assertEqual(self.observe()['status'], 'candidate_observed')
        self.clock.sleep(1)
        self.assertEqual(self.observe()['status'], 'verified')
        result = self.observe(rollback=True)
        self.assertEqual(result['status'], 'rollback_user_restart_required')
        self.assertEqual(self.c.manifest_path.read_bytes(), self.old_bytes)
        self.host.shallow = False
        self.assertEqual(self.w.tick(self.c, grace=0)['status'], 'suspect')
        self.assertEqual(self.w.tick(self.c, grace=0)['status'], 'blocked')
        self.assertEqual(self.host.calls, [])
        u.admit(self.base, self.pin, self.version)

    def test_installed_candidate_stability_resets_on_identity_or_health_change(self):
        self.stage_select()
        self.launch('webui')
        self.launch('agent')
        first = self.observe()
        self.assertEqual(first['status'], 'candidate_observed')
        self.clock.sleep(1)
        self.launch('webui')
        replacement = self.observe()
        self.assertGreater(replacement['stable_since'], first['stable_since'])
        self.clock.sleep(1)
        self.assertEqual(self.observe()['status'], 'candidate_observed')
        self.host.deep = False
        self.assertEqual(self.observe()['status'], 'transition_unhealthy')
        self.host.deep = True
        self.assertEqual(self.observe()['status'], 'candidate_observed')
        self.clock.sleep(2)
        result = self.observe()
        self.assertEqual(result['status'], 'verified')
        self.assertEqual(json.loads((self.base/self.w.RESULT).read_bytes()), result)
        self.assertEqual(self.host.calls, [])

    def test_installed_unknown_owner_fails_closed(self):
        self.stage_select()
        self.processes[self.host.jobs['webui']['pid']+1]['uid'] = os.getuid()+1
        for _ in range(3):
            self.assertEqual(self.w.tick(self.c, grace=0)['status'], 'blocked')
        self.assertEqual(self.c.manifest_path.read_bytes(), self.candidate.read_bytes())
        self.assertEqual(self.host.calls, [])

    def test_installed_liveness_repair_consumes_old_not_candidate(self):
        self.stage_select()
        self.host.shallow = False
        consumed = []
        self.host.kickstart = lambda target: consumed.append((target, self.c.manifest_path.read_bytes()))
        self.assertEqual(self.w.tick(self.c, grace=0)['status'], 'suspect')
        self.assertEqual(self.w.tick(self.c, grace=0)['status'], 'restart_requested')
        self.assertEqual(consumed, [(self.c.target(self.old, 'webui'), self.old_bytes)])

    def test_installed_timeout_with_gateway_first_and_late_candidate(self):
        self.stage_select()
        self.launch('agent')
        mixed = self.w.tick(self.c, grace=0)
        self.assertEqual(mixed['pending']['running'], dict(agent='new', webui='old'))
        self.clock.sleep(61)
        result = self.observe()
        self.assertEqual((result['selected'], result['reason']), ('old', 'expired'))
        self.launch('webui')
        self.assertEqual(self.observe()['status'], 'rollback_user_restart_required')
        self.assertEqual(self.host.calls, [])


if __name__ == '__main__':
    unittest.main()
