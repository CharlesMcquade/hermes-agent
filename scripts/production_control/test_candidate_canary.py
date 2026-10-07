"""stdlib tests: no app imports, credentials, services, pytest or dependency installs."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import candidate_canary as c

SYSTEM_PYTHON = '/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/Resources/Python.app/Contents/MacOS/Python'
SYSTEM_RUNTIME = '/Library/Developer/CommandLineTools'


class HarnessTests(unittest.TestCase):
    def setUp(self):
        c.BASE.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix='test-', dir=c.BASE)
        self.root = Path(self.tmp.name)
        c.initialize(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_environment_is_constructed(self):
        with patch.dict(os.environ, {'API_KEY': 'never-copy', 'HOME': '/real',
                                    'HERMES_HOME': '/real', 'PYTHONPATH': '/evil',
                                    'HTTPS_PROXY': 'http://evil', '_HERMES_GATEWAY': '1'}):
            env = c.clean_env(self.root)
        for name in ('API_KEY', 'HTTPS_PROXY', '_HERMES_GATEWAY', 'PYTHONPATH'):
            self.assertNotIn(name, env)
        self.assertEqual(env['HOME'], str(self.root / 'home'))
        self.assertEqual(env['PYTHONDONTWRITEBYTECODE'], '1')

    def test_config_has_no_delivery_or_real_state(self):
        cfg = json.loads((self.root / 'state/config.yaml').read_text())
        self.assertEqual(cfg['platforms'], {})
        self.assertEqual(cfg['mcp_servers'], {})
        self.assertEqual(cfg['plugins']['enabled'], [])
        self.assertFalse(cfg['gateway']['multiplex_profiles'])
        self.assertFalse(cfg['kanban']['dispatch_in_gateway'])

    def test_inventory_detects_new_changed_deleted_bytes(self):
        p = self.root / 'repo'; p.mkdir(); f = p / 'a'; f.write_text('a')
        before = c.inventory(p)
        f.write_text('b'); self.assertNotEqual(c.inventory(p), before)
        f.write_text('a'); self.assertEqual(c.inventory(p), before)
        (p / 'new.pyc').write_bytes(b'cache'); self.assertNotEqual(c.inventory(p), before)
        (p / 'new.pyc').unlink(); f.unlink(); self.assertNotEqual(c.inventory(p), before)

    def test_inventory_includes_git_and_modes(self):
        p = self.root / 'repo'; (p / '.git').mkdir(parents=True)
        f = p / '.git/HEAD'; f.write_text('one')
        before = c.inventory(p)
        f.chmod(0o700); self.assertNotEqual(before, c.inventory(p))

    def test_external_symlinks_rejected(self):
        p = self.root / 'repo'; p.mkdir(); (p / 'escape').symlink_to(self.root / 'home')
        with self.assertRaisesRegex(RuntimeError, 'External symlink'): c.inventory(p)

    def test_fake_git_ref_is_not_authentic(self):
        p = self.root / 'repo'; (p / '.git/refs/heads').mkdir(parents=True)
        (p / '.git/HEAD').write_text('ref: refs/heads/master\n')
        (p / '.git/refs/heads/master').write_text('a' * 40 + '\n')
        with self.assertRaisesRegex(RuntimeError, 'Git'):
            c.git_identity(p, 'a' * 40, c.clean_env(self.root))

    def test_malformed_sha_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'Invalid SHA'):
            c.git_identity(self.root, 'made-up', c.clean_env(self.root))

    def test_command_always_sandbox_and_no_bytecode(self):
        result = c.cmd('/p', '/python', '-m', 'gateway.run')
        self.assertEqual(result, ['/usr/bin/sandbox-exec', '-f', '/p', '/python', '-B', '-s', '-m', 'gateway.run'])

    def test_actual_os_containment_and_child_inheritance(self):
        policy = self.root / 'sandbox.sb'
        policy.write_text(c.sandbox_policy(self.root, [SYSTEM_RUNTIME], 59997, [SYSTEM_PYTHON]))
        result = c.prove_isolation(self.root, SYSTEM_PYTHON, policy, c.clean_env(self.root))
        for field in ('read_denied', 'write_denied', 'other_loopback_denied', 'external_denied', 'shell_denied'):
            self.assertTrue(result[field]); self.assertTrue(result['child_inheritance'][field])

    def test_allowed_listener_reachable_and_reaped(self):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
        policy = self.root / 'sandbox.sb'
        policy.write_text(c.sandbox_policy(self.root, [SYSTEM_RUNTIME], port, [SYSTEM_PYTHON]))
        # Fixture is solely a sandbox transport test, NOT a candidate application substitute.
        proc = subprocess.Popen(c.cmd(policy, SYSTEM_PYTHON, '-c',
            'import http.server; http.server.HTTPServer(("127.0.0.1",'+str(port)+'),http.server.BaseHTTPRequestHandler).serve_forever()'),
            env=c.clean_env(self.root), cwd=self.root, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            import time
            until = time.monotonic() + 5
            while True:
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.3): break
                except OSError:
                    if time.monotonic() >= until: raise
                    time.sleep(.1)
        finally:
            c.stop(proc)
        self.assertIsNotNone(proc.poll())
        with self.assertRaises(OSError): socket.create_connection(('127.0.0.1', port), timeout=.3)

    def test_scratch_inside_payload_refused_before_any_write(self):
        runtime = self.root / 'runtime'; runtime.mkdir()
        before = c.inventory(runtime)
        args = argparse.Namespace(runtime=str(runtime), python=str(runtime / 'venv/bin/python'),
                                  agent=None, webui=None, agent_sha='a' * 40,
                                  webui_sha='b' * 40, isolation_only=True)
        with patch.object(c, 'BASE', runtime / 'scratch'):
            with self.assertRaisesRegex(RuntimeError, 'Scratch directory'):
                c.run(args)
        self.assertEqual(c.inventory(runtime), before)

    def test_unproven_isolation_cannot_launch(self):
        runtime = self.root / 'runtime'
        python = runtime / 'venv/bin/python'
        python.parent.mkdir(parents=True)
        python.write_text('never executed')
        (self.root / 'agent').mkdir()
        args = argparse.Namespace(python=str(python), runtime=str(runtime),
                                  agent=str(self.root / 'agent'), webui=str(self.root / 'webui'),
                                  agent_sha='a' * 40, webui_sha='b' * 40, isolation_only=False)
        before = set(c.BASE.glob('canary-*'))
        with patch.object(c, 'git_identity'), patch.object(c, 'inventory', return_value={}), patch.object(c, 'prove_isolation', side_effect=RuntimeError('blocked')), patch.object(c.subprocess, 'Popen') as launch:
            with self.assertRaisesRegex(RuntimeError, 'blocked'): c.run(args)
            launch.assert_not_called()
        new = (set(c.BASE.glob('canary-*')) - before).pop()
        report = json.loads((new / 'report.json').read_text())
        self.assertEqual(report['status'], 'failed')
        self.assertTrue(report['cleanup']['state_removed'])
        self.assertFalse((new / 'state').exists())

    def cleanup_run(self, probe, removal_error=False):
        runtime = self.root / 'runtime'
        python = runtime / 'venv/bin/python'
        python.parent.mkdir(parents=True)
        python.write_text('not executed')
        args = argparse.Namespace(python=str(python), runtime=str(runtime),
                                  agent=None, webui=None, agent_sha='a' * 40,
                                  webui_sha='b' * 40, isolation_only=True)
        with patch.object(c, 'BASE', self.root), patch.object(c, 'prove_isolation', side_effect=probe):
            if removal_error:
                with patch.object(c.os, 'rmdir', side_effect=PermissionError('injected cleanup failure')):
                    with self.assertRaisesRegex(RuntimeError, 'original probe failure'):
                        c.run(args)
            else:
                c.run(args)
        run = next(self.root.glob('canary-*'))
        return run, json.loads((run / 'report.json').read_text())

    def test_readonly_copied_skills_cleanup(self):
        def probe(root, *unused):
            leaf = root / 'state/skills/media/gif-search'
            leaf.mkdir(parents=True)
            (leaf / 'SKILL.md').write_text('fixture')
            for directory in (leaf, leaf.parent, leaf.parent.parent):
                directory.chmod(0o555)
            return {'fixture': True}
        run, report = self.cleanup_run(probe)
        self.assertEqual(report['status'], 'isolation_proven')
        self.assertTrue(report['cleanup']['state_removed'])
        self.assertFalse((run / 'state').exists())

    def test_cleanup_never_follows_outside_symlinks(self):
        outside = self.root / 'outside'; outside.mkdir()
        target = outside / 'keep'; target.write_text('unchanged')
        outside.chmod(0o555)
        def probe(root, *unused):
            (root / 'state/escape').symlink_to(outside, target_is_directory=True)
            (root / 'tmp').rmdir()
            (root / 'tmp').symlink_to(outside, target_is_directory=True)
            return {}
        run, report = self.cleanup_run(probe)
        self.assertTrue(report['cleanup']['state_removed'])
        self.assertEqual(target.read_text(), 'unchanged')
        self.assertEqual(outside.stat().st_mode & 0o777, 0o555)
        self.assertFalse((run / 'tmp').is_symlink())

    def test_cleanup_exception_preserves_original_and_receipt(self):
        def probe(*unused):
            raise RuntimeError('original probe failure')
        run, report = self.cleanup_run(probe, removal_error=True)
        self.assertEqual(report['status'], 'failed')
        self.assertEqual(report['error'], 'original probe failure')
        self.assertFalse(report['cleanup']['state_removed'])
        self.assertEqual(set(report['cleanup']['remaining']), {'home', 'state', 'webui', 'tmp'})
        self.assertTrue(any('injected cleanup failure' in e for e in report['cleanup']['errors']))

    def test_incomplete_cleanup_cannot_certify_success(self):
        def probe(*unused):
            return {}
        with patch.object(c, 'remove_disposable', side_effect=PermissionError('blocked removal')):
            with self.assertRaisesRegex(RuntimeError, 'blocked removal'):
                self.cleanup_run(probe)
        run = next(self.root.glob('canary-*'))
        report = json.loads((run / 'report.json').read_text())
        self.assertEqual(report['status'], 'failed')
        self.assertFalse(report['cleanup']['state_removed'])

    def test_sandbox_git_identity_is_not_hidden(self):
        repo = self.root / 'repo'
        repo.mkdir()
        env = c.clean_env(self.root)
        def git(*args):
            return subprocess.run(['/usr/bin/git', '-C', str(repo), *args],
                                  env=env, check=True, capture_output=True, text=True).stdout.strip()
        git('init')
        git('-c', 'user.name=Canary', '-c', 'user.email=canary@example.invalid',
            'commit', '--allow-empty', '-m', 'fixture')
        expected = git('rev-parse', 'HEAD')
        policy = self.root / 'sandbox.sb'
        policy.write_text(c.sandbox_policy(self.root, [SYSTEM_RUNTIME], 59997, [SYSTEM_PYTHON]))
        result = subprocess.run(c.cmd(policy, SYSTEM_PYTHON, '-c',
            'import subprocess; p=subprocess.run(["git","rev-parse","HEAD"],capture_output=True,text=True); print(p.stdout.strip()); print(p.stderr); raise SystemExit(p.returncode)'),
            cwd=repo, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.splitlines()[0], expected)

    def test_static_mimetypes_os_database_readable(self):
        policy = self.root / 'sandbox.sb'
        policy.write_text(c.sandbox_policy(self.root, [SYSTEM_RUNTIME], 59997, [SYSTEM_PYTHON]))
        result = subprocess.run(c.cmd(policy, SYSTEM_PYTHON, '-c',
            'import mimetypes; mimetypes.init(); assert mimetypes.guess_type("boot.js")[0]'),
            cwd=self.root, env=c.clean_env(self.root), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
