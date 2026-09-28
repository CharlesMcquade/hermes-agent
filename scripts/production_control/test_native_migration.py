"""Offline legacy/native activation uses the existing durable transaction."""
import copy
import os
from pathlib import Path
import plistlib
import unittest

import restart_production as control
import test_native_identity as native_fixtures


class NativeMigrationTests(unittest.TestCase):
    def setUp(self):
        fixture = native_fixtures.NativeTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.base, self.clock = fixture.base, fixture.clock
        self.c, self.host = fixture.c, fixture.host
        self.plists = fixture.plists
        self.new = copy.deepcopy(fixture.manifest)
        self.old = copy.deepcopy(self.new)
        del self.old['native_host']
        self.new['release_id'] = 'native-candidate'
        anchor = self.base / 'native-anchor'
        anchor.mkdir()
        self.new['launchd_overrides'] = {}
        for s, path in self.plists.items():
            data = plistlib.loads(path.read_bytes())
            self.new['launchd_overrides'][s] = dict(
                ProgramArguments=[self.new['native_host']['executable'], s],
                WorkingDirectory=str(anchor),
                AssociatedBundleIdentifiers=[self.new['native_host']['bundle_id']],
                AbandonProcessGroup=False,
            )
            data['ProgramArguments'] = ['/usr/bin/python3', str(self.base / 'production_launcher.py'), s]
            data['Program'] = data['ProgramArguments'][0]
            del data['AssociatedBundleIdentifiers']
            data['AbandonProcessGroup'] = True
            # Binary input ensures rollback restores bytes, not just dictionary values.
            path.write_bytes(plistlib.dumps(data, fmt=plistlib.FMT_BINARY))
            self.host.jobs[s].update(argv=data['ProgramArguments'], cwd=data['WorkingDirectory'])
        control.save_json(self.c.manifest_path, self.old)
        self.host.listener = lambda url: {
            self.host.jobs['webui']['pid'] + (1 if self.native_job('webui') else 0)}
        self.host.process_identity = self.process_identity
        self.candidate = self.base / 'native-candidate.json'

    def native_job(self, service):
        return self.host.jobs[service]['argv'] == [self.new['native_host']['executable'], service]

    def process_identity(self, pid):
        for s, job in self.host.jobs.items():
            if pid in (job['pid'], job['pid'] + 1):
                child = pid != job['pid']
                argv = self.new['services'][s]['argv'] if child else job['argv']
                return dict(pid=pid, ppid=job['pid'] if child else 1,
                            uid=os.getuid(), executable=str(Path(argv[0]).resolve()),
                            argv=argv, start_time=self.host.started)
        raise AssertionError('Unexpected fixture PID')

    def saved(self):
        return {s: p.read_bytes() for s, p in self.plists.items()}

    def activate(self, candidate=None, reload=True):
        control.save_json(self.candidate, self.new if candidate is None else candidate)
        return self.c.restart(candidate=self.candidate, reload=reload, yes=True)

    def test_success_and_failed_start_restore_exact_legacy_bytes(self):
        for fail in (False, True):
            with self.subTest(fail=fail):
                if fail:
                    self.setUp()
                old_bytes, saved = self.c.manifest_path.read_bytes(), self.saved()
                old_jobs = copy.deepcopy(self.host.jobs)
                # A native child never becomes ready, rather than mocking readiness.
                if fail:
                    listener = self.host.listener
                    self.host.listener = lambda url: set() if self.native_job('webui') else listener(url)
                result = self.activate()
                self.assertEqual(result['status'], 'rolled_back' if fail else 'verified')
                txn = self.c.read_transaction()
                assert txn is not None
                self.assertEqual(txn['authorization'], 'verified-live-fallback')
                if fail:
                    self.assertEqual(self.c.manifest_path.read_bytes(), old_bytes)
                    self.assertEqual(self.saved(), saved)
                    for s in self.plists:
                        self.assertEqual(self.host.jobs[s]['argv'], old_jobs[s]['argv'])
                        self.assertEqual(self.host.jobs[s]['cwd'], old_jobs[s]['cwd'])
                        self.assertNotEqual(self.host.jobs[s]['pid'], old_jobs[s]['pid'])
                    self.c.snapshot(self.c.load(), self.c.definitions(self.c.load()))
                else:
                    self.assertEqual(self.c.load(), self.new)
                    for s, path in self.plists.items():
                        actual = plistlib.loads(path.read_bytes())
                        for key, value in self.new['launchd_overrides'][s].items():
                            self.assertEqual(actual[key], value)
                        self.assertIs(actual['AbandonProcessGroup'], False)
                        self.assertNotIn('Program', actual)
                        self.assertEqual(self.host.jobs[s]['argv'], actual['ProgramArguments'])
                    self.c.snapshot(self.c.load(), self.c.definitions(self.c.load()))

    def test_invalid_or_implicit_migrations_refuse_before_changes(self):
        cases = []
        for field, values in {
            'AssociatedBundleIdentifiers': ['foreign', [], ['foreign'],
                                           [self.new['native_host']['bundle_id'], 'foreign'], False, {}],
            'AbandonProcessGroup': [True, 0, 1, 'false', None, []],
            'ProgramArguments': [['/wrong', 'webui'], 'wrong', [],
                                 [self.new['native_host']['executable'], 'agent']],
            'WorkingDirectory': [0, None, 'relative', '/nonexistent-native-anchor'],
            'Program': ['/wrong'],
        }.items():
            for value in values:
                candidate = copy.deepcopy(self.new)
                candidate['launchd_overrides']['webui'][field] = value
                cases.append((field, candidate, True))
        for field in self.new['launchd_overrides']['webui']:
            candidate = copy.deepcopy(self.new)
            del candidate['launchd_overrides']['webui'][field]
            cases.append(('missing ' + field, candidate, True))
        candidate = copy.deepcopy(self.new)
        del candidate['launchd_overrides']['webui']
        cases.append(('missing service', candidate, True))
        cases.append(('no reload', self.new, False))
        for field in ('AssociatedBundleIdentifiers', 'AbandonProcessGroup'):
            candidate = copy.deepcopy(self.old)
            candidate['launchd_overrides'] = {'webui': {
                'ProgramArguments': self.host.jobs['webui']['argv'],
                'WorkingDirectory': str(self.base),
                field: self.new['launchd_overrides']['webui'][field]}}
            cases.append(('legacy ' + field, candidate, True))
        old_bytes, saved = self.c.manifest_path.read_bytes(), self.saved()
        for name, candidate, reload in cases:
            with self.subTest(name=name, candidate=candidate):
                with self.assertRaises(control.ControlError):
                    self.activate(candidate, reload)
                self.assertEqual(self.host.calls, [])
                self.assertEqual(self.c.manifest_path.read_bytes(), old_bytes)
                self.assertEqual(self.saved(), saved)
                self.assertFalse(self.c.transaction_path.exists())
        native_defs = self.c.candidate_definitions(self.old, self.new, saved, True)
        native_saved = {s: plistlib.dumps(d) for s, d in native_defs.items()}
        self.assertEqual(self.c.candidate_definitions(self.new, self.new, native_saved, False), native_defs)
        # Policy-only edits (including integer zero -> boolean false) still reload.
        for value in (True, 0):
            data = dict(native_defs['webui'], AbandonProcessGroup=value)
            changed = dict(native_saved, webui=plistlib.dumps(data))
            with self.subTest(policy=value), self.assertRaisesRegex(control.ControlError, '--reload'):
                self.c.candidate_definitions(self.new, self.new, changed, False)
        # Even direct candidate construction cannot erase an unrelated Program.
        for program in ('/foreign', None, 0):
            damaged = dict(saved)
            data = plistlib.loads(damaged['webui'])
            if program is None:
                program = ['/foreign']
            data['Program'] = program
            damaged['webui'] = plistlib.dumps(data)
            with self.subTest(program=program), self.assertRaisesRegex(control.ControlError, 'Conflicting'):
                self.c.candidate_definitions(self.old, self.new, damaged, True)
