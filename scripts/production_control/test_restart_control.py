"""Isolated fault tests: python3 -m unittest discover -s scripts/production_control -p test_restart_control.py -v"""
import copy
import json
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest.mock import patch

from restart_production import Controller, ControlError, ASSETS, control_lock, parse_job, save_json
from watchdog import tick
from approved_restart_job import main as approved_main


class Clock:
    value = 1700000000.0
    def __call__(self):
        return self.value
    def sleep(self, duration):
        self.value += duration


class FakeHost:
    def __init__(self, fixture):
        self.f = fixture
        self.calls = []
        self.jobs = {}
        self.started = fixture.clock()
        self.shallow = True
        self.deep = True
        self.asset_bad = False
        self.fail_kicks = set()
        self.kicks = 0
        for s in ('agent', 'webui'):
            data = plistlib.loads(fixture.plists[s].read_bytes())
            self.jobs[s] = {'argv': data['ProgramArguments'], 'cwd': data['WorkingDirectory'], 'pid': 100 if s == 'agent' else 200}
    def service(self, target):
        return target.rsplit('/', 1)[1]
    def job(self, target):
        return copy.deepcopy(self.jobs[self.service(target)])
    def kickstart(self, target):
        s = self.service(target)
        self.calls.append(('kickstart', s))
        self.kicks += 1
        if self.kicks in self.fail_kicks:
            raise ControlError('injected launchctl failure')
        self.jobs[s]['pid'] += 10
        self.started = self.f.clock()
        if s == 'agent':
            self.f.write_gateway(self.jobs[s]['pid'] + 1)
    def reload(self, target, plist):
        s = self.service(target)
        self.calls.append(('reload', s))
        data = plistlib.loads(Path(plist).read_bytes())
        self.jobs[s].update(argv=data['ProgramArguments'], cwd=data['WorkingDirectory'])
        self.kickstart(target)
    def fetch(self, url):
        if '/static/' in url:
            return b'wrong' if self.asset_bad else b'asset'
        ok = self.deep if 'deep=1' in url else self.shallow
        return json.dumps({'status': 'ok' if ok else 'bad', 'server_started_at': self.started}).encode()
    def listener(self, url):
        return {self.jobs['webui']['pid']}
    def descendant(self, child, parent):
        return child == parent + 1


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.clock = Clock()
        self.plists = {s: self.base / (s + '.plist') for s in ('agent', 'webui')}
        self.manifest = {'schema_version': 2, 'state_dir': str(self.base), 'health_url': 'http://127.0.0.1:12345/health',
                         'labels': {'agent': 'agent', 'webui': 'webui'}, 'services': {}}
        (self.base / 'static').mkdir()
        for name in ASSETS:
            (self.base / 'static' / name).write_bytes(b'asset')
        for s in self.plists:
            self.manifest['services'][s] = {'repo': str(self.base), 'cwd': str(self.base), 'commit': 'abc123', 'plist_path': str(self.plists[s])}
            self.plists[s].write_bytes(plistlib.dumps({'Label': s, 'ProgramArguments': ['/usr/bin/python3', str(self.base / 'production_launcher.py'), s],
                                                      'WorkingDirectory': str(self.base), 'KeepAlive': True, 'RunAtLoad': True}))
        save_json(self.base / 'production-release.json', self.manifest)
        self.host = FakeHost(self)
        self.preflights = []
        self.c = Controller(self.base, self.host, self.preflight, self.clock, self.clock, self.clock.sleep,
                            owner=lambda: 1, timeout=5, stable_seconds=1)
        self.write_gateway(101)
    def preflight(self, manifest):
        self.preflights.append(manifest['services']['agent']['commit'])
        if manifest.get('broken'):
            raise ControlError('broken runtime')
    def write_gateway(self, pid):
        manifest = json.loads((self.base / 'production-release.json').read_text())
        save_json(self.base / 'gateway_state.json', {'pid': pid, 'code_sha': manifest['services']['agent']['commit'],
                  'gateway_state': 'running', 'updated_at': self.clock()})
    def candidate(self, **updates):
        data = copy.deepcopy(self.manifest)
        data.update(updates)
        path = self.base / 'candidate.json'
        save_json(path, data)
        return path
    def test_restart_verified_without_bootout(self):
        result = self.c.restart(yes=True)
        self.assertEqual(result['status'], 'verified')
        self.assertEqual(self.host.calls, [('kickstart', 'agent'), ('kickstart', 'webui')])
        self.assertEqual(result['gateway_child_pid'], result['pids']['agent'] + 1)
        self.assertEqual(json.loads((self.base / 'restart-result.json').read_text()), result)
    def test_preflight_failure_never_stops(self):
        with self.assertRaisesRegex(ControlError, 'broken runtime'):
            self.c.restart(candidate=self.candidate(broken=True), yes=True)
        self.assertEqual(self.host.calls, [])
        self.assertEqual(json.loads((self.base / 'restart-result.json').read_text())['status'], 'failed')
    def test_loaded_argv_drift_never_stops(self):
        self.host.jobs['webui']['argv'].append('--evil')
        with self.assertRaisesRegex(ControlError, 'drift'):
            self.c.restart(yes=True)
        self.assertEqual(self.host.calls, [])
    def test_loaded_cwd_drift_never_stops(self):
        self.host.jobs['agent']['cwd'] = '/other'
        with self.assertRaisesRegex(ControlError, 'drift'):
            self.c.restart(yes=True)
        self.assertEqual(self.host.calls, [])
    def test_failure_restores_exact_manifest_and_plists(self):
        old = (self.base / 'production-release.json').read_bytes()
        saved = {s: p.read_bytes() for s, p in self.plists.items()}
        candidate = copy.deepcopy(self.manifest)
        candidate['services']['agent']['commit'] = 'def456'
        path = self.candidate(**candidate)
        self.host.fail_kicks = {2}
        result = self.c.restart(candidate=path, yes=True)
        self.assertEqual(result['status'], 'rolled_back')
        self.assertEqual((self.base / 'production-release.json').read_bytes(), old)
        self.assertEqual({s: p.read_bytes() for s, p in self.plists.items()}, saved)
        self.assertEqual(self.host.kicks, 4)
        events = [json.loads(line) for line in (self.base / 'restart-journal.jsonl').read_text().splitlines()]
        self.assertEqual([x['status'] for x in events], ['prepared', 'failed', 'rolled_back'])
        self.assertEqual(len({x['operation_id'] for x in events}), 1)
    def test_recovery_failure_bounded(self):
        self.host.fail_kicks = {1, 2, 3}
        self.assertEqual(self.c.restart(yes=True)['status'], 'rollback_failed')
        self.assertEqual(self.host.kicks, 2)
    def test_non_independent_owner_rejected(self):
        self.c.owner = lambda: 45
        with self.assertRaisesRegex(ControlError, 'ppid 1'):
            self.c.restart(yes=True)
        self.assertEqual(self.host.calls, [])
    def test_confirmation_required(self):
        with self.assertRaises(ControlError):
            self.c.restart()
        self.assertEqual(self.host.calls, [])
    def test_shared_lock_blocks_restart_and_watchdog(self):
        with control_lock(self.base):
            with self.assertRaisesRegex(ControlError, 'control.lock'):
                self.c.restart(yes=True)
            self.assertEqual(tick(self.c)['status'], 'busy')
        self.assertEqual(self.host.calls, [])
    def test_stale_gateway_and_wrong_sha_rejected(self):
        for field, value in [('updated_at', self.clock() + 120), ('code_sha', 'bad'), ('pid', 999)]:
            self.write_gateway(101)
            path = self.base / 'gateway_state.json'
            state = json.loads(path.read_text())
            state[field] = value
            save_json(path, state)
            with self.subTest(field=field), self.assertRaises(ControlError):
                self.c.snapshot(self.manifest, self.c.definitions(self.manifest))
    def test_stale_web_start_rejected(self):
        with self.assertRaisesRegex(ControlError, 'server_started_at'):
            self.c.snapshot(self.manifest, self.c.definitions(self.manifest), since=self.clock() + 10)
    def test_asset_corruption_rejected(self):
        self.host.asset_bad = True
        with self.assertRaisesRegex(ControlError, 'asset mismatch'):
            self.c.snapshot(self.manifest, self.c.definitions(self.manifest))
    def test_listener_must_be_same_pid(self):
        with patch.object(self.host, 'listener', return_value={999}):
            with self.assertRaisesRegex(ControlError, 'listener'):
                self.c.snapshot(self.manifest, self.c.definitions(self.manifest))
    def test_activation_changes_pointer_and_verifies_child(self):
        data = copy.deepcopy(self.manifest)
        data['services']['agent']['commit'] = 'newcommit'
        result = self.c.restart(candidate=self.candidate(**data), yes=True)
        self.assertEqual(result['status'], 'verified')
        self.assertEqual(self.c.load()['services']['agent']['commit'], 'newcommit')
    def test_reload_is_explicit_and_restores_drift(self):
        self.host.jobs['webui']['argv'] = ['old']
        self.assertEqual(self.c.restart(reload=True, yes=True)['status'], 'verified')
        self.assertIn(('reload', 'webui'), self.host.calls)
    def test_reload_failure_restores_cwd_and_plists(self):
        data = copy.deepcopy(self.manifest)
        data['services']['webui']['cwd'] = str(self.base / 'new-cwd')
        original = self.plists['webui'].read_bytes()
        self.host.fail_kicks = {2}
        result = self.c.restart(candidate=self.candidate(**data), reload=True, yes=True)
        self.assertEqual(result['status'], 'rolled_back')
        self.assertEqual(self.plists['webui'].read_bytes(), original)
        self.assertEqual(self.host.jobs['webui']['cwd'], str(self.base))

    def test_runtime_cwd_change_keeps_stable_launchd_anchor(self):
        data = copy.deepcopy(self.manifest)
        data['services']['webui']['cwd'] = str(self.base / 'new-cwd')
        result = self.c.restart(candidate=self.candidate(**data), yes=True)
        self.assertEqual(result['status'], 'verified')
        self.assertEqual(self.host.jobs['webui']['cwd'], str(self.base))
        self.assertEqual(self.host.calls, [('kickstart', 'agent'), ('kickstart', 'webui')])

    def test_idle_gateway_state_is_not_a_heartbeat(self):
        self.clock.sleep(3600)
        proof = self.c.snapshot(self.manifest, self.c.definitions(self.manifest))
        self.assertEqual(proof['gateway_child_pid'], 101)
        self.host.started = self.clock()
        with self.assertRaisesRegex(ControlError, 'predates restart'):
            self.c.snapshot(self.manifest, self.c.definitions(self.manifest), since=self.clock())

    def test_watchdog_requires_two_failures_and_cooldown(self):
        self.host.shallow = False
        self.assertEqual(tick(self.c, grace=0)['status'], 'suspect')
        self.assertEqual(tick(self.c, grace=0)['status'], 'restart_requested')
        self.assertEqual(self.host.calls, [('kickstart', 'webui')])
        tick(self.c, grace=0)
        self.assertEqual(tick(self.c, grace=0)['status'], 'cooldown')
        self.assertEqual(self.host.kicks, 1)
    def test_watchdog_deep_failure_never_restarts(self):
        self.host.deep = False
        for _ in range(3):
            self.assertEqual(tick(self.c, grace=0)['status'], 'degraded')
        self.assertEqual(self.host.calls, [])
    def test_watchdog_new_pid_grace(self):
        self.host.shallow = False
        self.assertEqual(tick(self.c)['status'], 'grace')
        self.clock.sleep(91)
        self.assertEqual(tick(self.c)['status'], 'suspect')
        self.host.jobs['webui']['pid'] += 1
        self.assertEqual(tick(self.c)['status'], 'grace')
        self.assertEqual(self.host.calls, [])
    def test_watchdog_preflight_failure_no_kick(self):
        self.host.shallow = False
        save_json(self.base / 'production-release.json', dict(self.manifest, broken=True))
        tick(self.c, grace=0)
        result = tick(self.c, grace=0)
        self.assertEqual(result['status'], 'blocked')
        self.assertGreater(result['next_attempt'], self.clock())
        self.assertEqual(self.host.calls, [])
    def test_watchdog_http_200_bad_json_is_failure(self):
        with patch.object(self.host, 'fetch', return_value=b'<html>ok</html>'):
            self.assertEqual(tick(self.c, grace=0)['status'], 'suspect')
    def test_watchdog_drift_never_restarts(self):
        self.host.jobs['webui']['argv'] = ['unrelated']
        self.host.shallow = False
        self.assertEqual(tick(self.c, grace=0)['status'], 'blocked')
        self.assertEqual(self.host.calls, [])
    def test_real_launcher_preflight_and_tamper_refusal(self):
        import sys
        from production_launcher import inventory
        repo = self.base / 'frozen'
        repo.mkdir()
        (repo / 'probe_fixture.py').write_text('VALUE = 1\n')
        data = copy.deepcopy(self.manifest)
        for item in data['services'].values():
            item.update(repo=str(repo), argv=[sys.executable, '-c', 'pass'],
                        inventory=inventory(repo), probe_modules=['probe_fixture'])
        save_json(self.base / 'production-release.json', data)
        c = Controller(self.base, host=self.host, owner=lambda: 1)
        c.preflight(c.load())  # Real hashes + isolated interpreter import.
        (repo / 'probe_fixture.py').write_text('VALUE = 2\n')
        with self.assertRaisesRegex(RuntimeError, 'content mismatch'):
            c.restart(yes=True)
        self.assertEqual(self.host.calls, [])

    def test_readiness_requires_stable_child(self):
        before = self.c.loaded(self.manifest, self.c.definitions(self.manifest))
        self.host.kickstart(self.c.target(self.manifest, 'agent'))
        self.host.kickstart(self.c.target(self.manifest, 'webui'))
        original = self.c.snapshot
        calls = []
        def unstable(*args):
            proof = original(*args)
            calls.append(1)
            proof['gateway_child_pid'] += len(calls)
            return proof
        with patch.object(self.c, 'snapshot', side_effect=unstable):
            with self.assertRaisesRegex(ControlError, 'timeout'):
                self.c.wait_ready(self.manifest, self.c.definitions(self.manifest), self.clock(), before)
        self.assertGreater(len(calls), 1)

    def test_approved_job_requires_owner_and_flags(self):
        with self.assertRaises(ControlError):
            approved_main(['--restart', '--yes'], owner=lambda: 20)
        with self.assertRaises(ControlError):
            approved_main([], owner=lambda: 1)
    def test_launchctl_parser_exact(self):
        text = 'gui/1/x = {\n\targuments = {\n\t\t/usr/bin/python3\n\t\t/a path/launcher.py\n\t\twebui\n\t}\n\tworking directory = /a path\n\tpid = 42\n}\n'
        self.assertEqual(parse_job(text), {'argv': ['/usr/bin/python3', '/a path/launcher.py', 'webui'], 'cwd': '/a path', 'pid': 42})
        with self.assertRaises(ControlError):
            parse_job('opaque launcher.py')


if __name__ == '__main__':
    unittest.main()
