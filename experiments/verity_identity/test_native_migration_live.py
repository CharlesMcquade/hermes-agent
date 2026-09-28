"""Offline boundary/receipt tests: never compile, sign, or contact launchd."""
import copy
import json
import os
from pathlib import Path
import plistlib
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_native_migration_live as m


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name).resolve()
        self.root = self.parent / ('verity-migration-' + 'a' * 32)
        self.identity = self.parent / 'identity.json'
        self.identity.write_text(json.dumps(dict(sha1='a' * 40, keychain=str(self.parent / 'lab.keychain'))))
        self.stack = []
        for name, value in [('SCRATCH', self.parent), ('IDENTITY', self.identity)]:
            p = patch.object(m, name, value)
            p.start()
            self.addCleanup(p.stop)

    def build(self):
        def run(argv, **kwargs):
            if argv[0] == '/usr/bin/xcrun':
                binary = Path(argv[-1])
                binary.write_bytes(b'offline fake compiler output, not live evidence')
                binary.chmod(0o700)
        return m.build(self.root, self.identity, live=True, runner=run)

    def test_opt_in_and_new_root_refused_before_writes(self):
        for root, live in [(self.root, False), (self.parent / 'production', True),
                           (self.parent / '..' / self.root.name, True)]:
            with self.assertRaises(ValueError):
                m.build(root, self.identity, live=live)
        self.assertFalse(self.root.exists())
        self.root.mkdir()
        with self.assertRaises(ValueError):
            m.build(self.root, self.identity, live=True)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_signer_refused_before_root_creation(self):
        with self.assertRaises(ValueError):
            m.build(self.root, self.parent / 'other.json', live=True)
        self.assertFalse(self.root.exists())

    def test_actual_manifest_and_plist_boundaries(self):
        old, native, bad, saved = self.build()
        m.validate_inputs(self.root, old, saved, sys.executable)
        for mutate in [lambda x: x['labels'].update(agent='com.hermes.agent'),
                       lambda x: x['services']['agent'].update(env_files=['/private/secret']),
                       lambda x: x['services']['webui'].update(repo='/Applications'),
                       lambda x: x.update(health_url='http://example.com/health'),
                       lambda x: x['services']['agent']['env'].update(HERMES_HOME='/real')]:
            changed = copy.deepcopy(old)
            mutate(changed)
            with self.assertRaises(ValueError):
                m.validate_inputs(self.root, changed, saved, sys.executable)
        for field, value in [('Program', '/bin/sh'), ('Label', 'com.hermes.webui'),
                             ('StandardOutPath', '/private/output'), ('EnvironmentVariables', {'HOME': '/real'})]:
            changed = dict(saved)
            definition = plistlib.loads(changed['agent'])
            definition[field] = value
            changed['agent'] = plistlib.dumps(definition)
            with self.assertRaises(ValueError):
                m.validate_inputs(self.root, old, changed, sys.executable)
        (self.root / 'agent.out').symlink_to(self.parent / 'outside')
        with self.assertRaises(ValueError):
            m.validate_inputs(self.root, old, saved, sys.executable)

    def test_legacy_wrapper_scrubs_inherited_environment(self):
        self.build()
        import runpy
        seen = {}
        fake = SimpleNamespace(main=lambda: seen.update(os.environ))
        with patch.dict(os.environ, {'UNAPPROVED_SENTINEL': 'must-not-survive'}), \
                patch.dict(sys.modules, {'production_launcher': fake}), \
                patch.object(sys, 'path', list(sys.path)):
            runpy.run_path(str(self.root / 'production_launcher.py'), run_name='__main__')
        self.assertEqual(seen, m.environment(self.root))

    def test_program_migration_uses_real_controller_logic(self):
        old, native, bad, saved = self.build()
        c = m.Controller(self.root, host=SimpleNamespace(verify_native_bundle=lambda *a: True))
        definitions = c.candidate_definitions(old, native, saved, reload=True)
        for role in m.ROLES:
            self.assertNotIn('Program', definitions[role])
            self.assertEqual(definitions[role]['ProgramArguments'], [native['native_host']['executable'], role])
            self.assertEqual(plistlib.loads(saved[role])['Program'], sys.executable)
        with self.assertRaises(Exception):
            c.candidate_definitions(old, native, saved, reload=False)

    def test_independent_boundary_rejects_tampered_actual_plist_before_launchctl(self):
        old, native, bad, saved = self.build()
        approved = {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob('*')
                    if p.is_file() and p.name not in ('production-release.json', 'agent.plist', 'webui.plist')}
        approved.update({'saved/' + r + '.plist': saved[r] for r in m.ROLES})
        definition = plistlib.loads(saved['agent'])
        definition['Program'] = '/bin/sh'
        (self.root / 'agent.plist').write_bytes(plistlib.dumps(definition))
        with patch.object(m, 'launchctl', side_effect=AssertionError('must not contact launchd')):
            with self.assertRaisesRegex(ValueError, 'Unsafe actual plist'):
                m.independent(self.root, approved=approved)
        self.assertFalse((self.root / 'controller.plist').exists())

    def test_preflight_failure_never_publishes_success(self):
        built = self.build()
        with patch.object(m, 'build', return_value=built), patch.object(m.Controller, 'preflight',
                side_effect=ValueError('deliberate preflight refusal')), patch.object(m, 'launchctl',
                side_effect=AssertionError('must not launch')):
            with self.assertRaisesRegex(ValueError, 'deliberate'):
                m.verify(self.root, live=True)
        self.assertFalse((self.root / 'migration-success.json').exists())
        receipt = json.loads((self.root / 'migration-failed.json').read_text())
        self.assertEqual(receipt['status'], 'failed')
        self.assertFalse(receipt['cleanup_verified'])

    def test_cleanup_subprocess_errors_preserve_failure_and_visit_all_targets(self):
        built = self.build()
        visited = []
        def launch(*args, **kwargs):
            if args[0] == 'bootout':
                visited.append(args[-1])
                if len(visited) == 1:
                    raise m.subprocess.TimeoutExpired('launchctl', 30)
                raise OSError('launchctl unavailable')
            return SimpleNamespace(returncode=113 if args[0] == 'print' else 0)
        with patch.object(m, 'build', return_value=built), patch.object(m.Controller, 'preflight'), \
                patch.object(m.Controller, 'definitions', return_value={}), \
                patch.object(m.Controller, 'wait_ready', side_effect=ValueError('readiness failed')), \
                patch.object(m, 'launchctl', side_effect=launch), \
                patch.object(m, 'until', side_effect=lambda fn, *a: fn()), \
                patch.object(m, 'gone', side_effect=m.subprocess.SubprocessError('ps failed')):
            with self.assertRaises(RuntimeError):
                m.verify(self.root, live=True)
        self.assertEqual(len(visited), 2)
        receipt = json.loads((self.root / 'migration-failed.json').read_text())
        self.assertEqual(len(receipt['cleanup_errors']), 3)
        self.assertFalse(receipt['cleanup_verified'])
        self.assertFalse((self.root / 'migration-success.json').exists())

    def test_controller_cleanup_registered_before_bootstrap_and_checks_after_timeout(self):
        self.build()
        approved = {str(p.relative_to(self.root)): p.read_bytes()
                    for p in self.root.rglob('*') if p.is_file()
                    and 'compiler' not in p.relative_to(self.root).parts
                    and p.name not in ('production-release.json', 'agent.plist', 'webui.plist')}
        approved.update({'saved/' + r + '.plist': (self.root / 'saved' / (r + '.plist')).read_bytes()
                         for r in m.ROLES})
        attempted, calls = [], []
        def launch(*args, **kwargs):
            calls.append(args)
            if args[0] == 'bootstrap':
                self.assertEqual(len(attempted), 1, 'Register controller before partial bootstrap')
                raise m.subprocess.TimeoutExpired('fixture-bootstrap', 30)
            if args[0] == 'bootout':
                raise OSError('fixture-cleanup failure')
            return SimpleNamespace(returncode=113)
        with patch.object(m, 'launchctl', side_effect=launch):
            with self.assertRaises(RuntimeError):
                m.independent(self.root, approved=approved, attempted=attempted)
        self.assertEqual(len(attempted), 1)
        self.assertTrue(attempted[0].endswith('.controller'))
        self.assertEqual([x[0] for x in calls], ['print', 'bootstrap', 'bootout', 'print'])

    def test_cleanup_counts_failed_hosts_workers_guards_not_launchd(self):
        self.root.mkdir()
        (self.root / 'state').mkdir()
        (self.root / 'state/processes.jsonl').write_text('\n'.join(json.dumps(r) for r in [
            dict(pid=100, ppid=1, worker=101, pgid=100),
            dict(pid=201, ppid=200, worker=203, pgid=200)]))
        (self.root / 'webui.out').write_text(json.dumps(dict(event='service-host',
            pid=200, child_pid=201, guard_pid=202, pgid=200)) + '\n')
        e = m.evidence(self.root)
        self.assertEqual(e, ({100, 101, 200, 201, 202, 203}, {100, 200}))
        self.assertFalse(m.gone((set(), set())))
        with patch.object(m, 'alive', return_value=False), patch.object(m.subprocess, 'run',
                return_value=SimpleNamespace(stdout='999 200\n')):
            self.assertFalse(m.gone(e))
        with patch.object(m, 'alive', side_effect=lambda p: p == 202):
            self.assertFalse(m.gone(e))
        report = {'status': 'failed'}
        m.set_cleanup_outcome(report, [], ['attempted'])
        self.assertFalse(report['cleanup_verified'])


if __name__ == '__main__':
    unittest.main()
