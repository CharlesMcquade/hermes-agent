"""Stdlib-only regression tests: python -B -m unittest discover -s <this-dir>."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_workflow as workflow


class ReleaseWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        self.git(self.source, 'init', '-q')
        self.git(self.source, 'config', 'user.name', 'Fixture')
        self.git(self.source, 'config', 'user.email', 'fixture@example.invalid')
        (self.source / 'file.txt').write_text('approved\n')
        self.git(self.source, 'add', '.')
        self.git(self.source, 'commit', '-qm', 'fixture')
        self.sha = workflow.git(self.source, 'rev-parse', 'HEAD')
        self.repo = self.root / 'snapshot'
        workflow.snapshot(self.source, self.sha, self.repo)
        self.manifest = {'source_commits': {'agent': self.sha},
                         'services': {'agent': {'repo': str(self.repo), 'commit': self.sha}}}

    def git(self, repo, *args):
        return subprocess.run(['/usr/bin/git', '-C', str(repo), *args],
                              capture_output=True, check=True)

    def test_genuine_snapshot_and_commit_objects(self):
        result = workflow.provenance(self.manifest)
        self.assertEqual(result['agent']['commit'], self.sha)
        self.assertTrue((self.repo / '.git/objects').is_dir())

    def test_fabricated_ref_without_object_rejected(self):
        fake = '1' * 40
        (self.repo / '.git/HEAD').write_text(fake + '\n')
        self.manifest['source_commits']['agent'] = fake
        self.manifest['services']['agent']['commit'] = fake
        with self.assertRaises(RuntimeError):
            workflow.provenance(self.manifest)

    def test_missing_git_rejected(self):
        (self.repo / '.git').rename(self.repo / 'git-missing')
        with self.assertRaisesRegex(RuntimeError, 'genuine Git'):
            workflow.provenance(self.manifest)

    def test_stale_service_commit_rejected(self):
        self.manifest['services']['agent']['commit'] = '2' * 40
        with self.assertRaisesRegex(RuntimeError, 'manifest commit disagreement'):
            workflow.provenance(self.manifest)

    def test_stale_head_rejected(self):
        (self.repo / '.git/HEAD').write_text('2' * 40 + '\n')
        with self.assertRaises(RuntimeError):
            workflow.provenance(self.manifest)

    def test_modified_tracked_file_rejected(self):
        (self.repo / 'file.txt').write_text('unapproved\n')
        with self.assertRaisesRegex(RuntimeError, 'modified tracked'):
            workflow.provenance(self.manifest)

    def test_external_worktree_pointer_rejected(self):
        (self.repo / '.git').rename(self.root / 'moved-git')
        (self.repo / '.git').write_text('gitdir: ' + str(self.root / 'moved-git'))
        with self.assertRaisesRegex(RuntimeError, 'genuine Git'):
            workflow.provenance(self.manifest)

    def test_external_alternates_rejected(self):
        alternate = self.repo / '.git/objects/info/alternates'
        alternate.parent.mkdir(exist_ok=True)
        alternate.write_text(str(self.source / '.git/objects'))
        with self.assertRaisesRegex(RuntimeError, 'external Git'):
            workflow.provenance(self.manifest)

    def test_assume_unchanged_cannot_hide_modified_source(self):
        self.git(self.repo, 'update-index', '--assume-unchanged', 'file.txt')
        (self.repo / 'file.txt').write_text('unapproved\n')
        with self.assertRaisesRegex(RuntimeError, 'modified tracked'):
            workflow.provenance(self.manifest)

    def test_local_git_fsmonitor_is_not_executed(self):
        marker = self.root / 'hook-ran'
        hook = self.root / 'hook'
        hook.write_text('#!/bin/sh\ntouch "' + str(marker) + '"\n')
        hook.chmod(0o700)
        self.git(self.repo, 'config', 'core.fsmonitor', str(hook))
        workflow.provenance(self.manifest)
        self.assertFalse(marker.exists(), 'validation executed repository hook')

    def test_config_rejects_alias_and_overlapping_roots(self):
        cfg = {k: str(self.root / k) for k in ('baseline', 'output', 'scratch', 'agent_repo', 'webui_repo')}
        cfg.update(agent_commit=self.sha, webui_commit=self.sha)
        path = self.root / 'config.json'
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        for updates in ({'output': str(alias / 'new')},
                        {'output': str(self.root)},
                        {'scratch': str(self.root / 'output' / 'scratch')},
                        {'tool_path': '/bin:relative'},
                        {'evidence_dir': str(self.root / 'output' / 'evidence')}):
            with self.subTest(updates=updates):
                path.write_text(json.dumps(dict(cfg, **updates)))
                with self.assertRaises(RuntimeError):
                    workflow.config_read(path)

    def test_identity_probe_cannot_read_outside_fixture(self):
        # Candidate code tries to read a nonsecret stand-in for private state.
        from test_candidate_canary import SYSTEM_PYTHON, SYSTEM_RUNTIME
        outside = self.root / 'private-sentinel'
        outside.write_text('fixture-only')
        for package in ('hermes_cli', 'gateway'):
            (self.repo / package).mkdir()
            (self.repo / package / '__init__.py').touch()
        (self.repo / 'hermes_cli/main.py').write_text(
            'from pathlib import Path\n' + f'Path({str(outside)!r}).read_text()\n' +
            f'def _read_git_revision_fingerprint(p): return "git:HEAD:{self.sha}"\n')
        (self.repo / 'gateway/code_skew.py').write_text(
            f'def current_code_sha(): return "{self.sha}"\n')
        (self.repo / 'hermes_cli/version_info.py').write_text(
            f'def get_code_identity(): return {{"sha": "{self.sha}"}}\n')
        self.manifest['services']['agent'].update(
            argv=[SYSTEM_PYTHON], runtimes=[{'root': SYSTEM_RUNTIME}])
        with self.assertRaises(RuntimeError):
            workflow.runtime_identity(self.manifest, self.root)
        self.assertEqual(outside.read_text(), 'fixture-only')

    def test_probe_env_drops_credentials_and_real_home(self):
        with mock.patch.dict(os.environ, {'OPENAI_API_KEY': 'fixture-not-secret',
                                          'HOME': '/real-home', 'HERMES_HOME': '/real-state'}):
            result = workflow.isolated_env(self.root, [self.repo])
        self.assertNotIn('OPENAI_API_KEY', result)
        self.assertEqual(result['HOME'], str(self.root))
        self.assertEqual(result['PYTHONDONTWRITEBYTECODE'], '1')
        self.assertEqual(result['HERMES_HOME'], str(self.root / 'agent-home'))

    def test_rebase_preserves_nonpath_identity(self):
        original = {'native': {'bundle': '/Apps/Stable.app'}, 'argv': ['/old/venv/bin/python'], 'number': 2}
        changed = workflow.rebase_paths(original, '/old', '/new')
        self.assertEqual(changed['native'], original['native'])
        self.assertEqual(changed['argv'], ['/new/venv/bin/python'])
        self.assertEqual(original['argv'], ['/old/venv/bin/python'])
        self.assertEqual(changed['number'], 2)

    def test_config_rejects_branch_instead_of_commit(self):
        cfg = {k: str(self.root / k) for k in ('baseline', 'output', 'scratch', 'agent_repo', 'webui_repo')}
        cfg.update(agent_commit='main', webui_commit=self.sha)
        path = self.root / 'config.json'
        path.write_text(json.dumps(cfg))
        with self.assertRaisesRegex(RuntimeError, 'exact lowercase'):
            workflow.config_read(path)

    def test_build_seals_exact_fixture_and_preserves_baseline(self):
        import shutil
        old = self.root / 'old'
        runtime = old / 'runtime'
        base = runtime / 'python'
        from test_candidate_canary import SYSTEM_PYTHON
        source_base = subprocess.check_output([SYSTEM_PYTHON, '-B', '-s', '-c',
            'import sys; print(sys.base_prefix)'], env=workflow.isolated_env(self.root), text=True).strip()
        shutil.copytree(Path(source_base).resolve(), base, symlinks=True,
                        ignore=lambda d, names: [n for n in names if n == 'site-packages' or n == '__pycache__' or n.endswith('.pyc')])
        home = self.root / 'bootstrap'; home.mkdir()
        workflow.contained_command([str(base / 'bin/python3'), '-B', '-s', '-m', 'venv',
                                    '--without-pip', str(runtime / 'venv')], home, [runtime],
                                   writes=[runtime], exec_roots=[runtime])
        for package in ('hermes_cli', 'gateway'):
            (self.source / package).mkdir()
            (self.source / package / '__init__.py').touch()
        identity = ('import subprocess\nfrom pathlib import Path\n'
                    'def sha(): return subprocess.check_output(["/usr/bin/git", "-C", '
                    'str(Path(__file__).resolve().parents[1]), "rev-parse", "HEAD"], text=True).strip()\n')
        (self.source / 'hermes_cli/main.py').write_text(identity +
            'def _read_git_revision_fingerprint(p): return "git:HEAD:" + sha()\n')
        (self.source / 'hermes_cli/version_info.py').write_text(identity +
            'def get_code_identity(): return {"sha":sha()}\n')
        (self.source / 'gateway/code_skew.py').write_text(identity +
            'def current_code_sha(): return sha()\n')
        (self.source / 'hermes_cli/_launchers.py').write_text(
            'def ensure_install_launchers(repo, destination):\n'
            '    (destination / "fixture").write_text("fixture launcher")\n')
        self.git(self.source, 'add', '.')
        self.git(self.source, 'commit', '-qm', 'fixture identity')
        sha = workflow.git(self.source, 'rev-parse', 'HEAD')
        state = self.root / 'state'; state.mkdir()
        services = {}
        for name in ('agent', 'webui'):
            workflow.snapshot(self.source, sha, old / name)
            services[name] = dict(repo=str(old / name), cwd=str(state),
                argv=[str(runtime / 'venv/bin/python')], commit=sha, env={}, requires=[],
                inventory=workflow.launcher.inventory(old / name))
        services['agent']['runtimes'] = [dict(root=str(runtime), inventory=workflow.launcher.inventory(runtime))]
        baseline = self.root / 'baseline.json'
        baseline.write_bytes(workflow.encoded(dict(schema_version=2, release_id='old', state_dir=str(state),
            services=services, source_commits=dict(agent=sha, webui=sha))))
        before = workflow.canary.inventory(old)
        cfg = dict(baseline=str(baseline), output=str(self.root / 'new'), scratch=str(self.root / 'scratch'),
                   agent_repo=str(self.source), webui_repo=str(self.source), agent_commit=sha, webui_commit=sha)
        result = workflow.build(cfg)
        self.assertEqual(result['status'], 'static_verified_not_deployed')
        self.assertEqual(workflow.canary.inventory(old), before)
        workflow.require_sealed(self.root / 'new')
        self.assertEqual(workflow.verify(cfg)['manifest_sha256'], result['manifest_sha256'])

    def test_git_replacements_and_includes_do_not_redefine_provenance(self):
        tree = workflow.git(self.repo, 'rev-parse', 'HEAD^{tree}')
        (self.source / 'file.txt').write_text('replacement\n')
        self.git(self.source, 'commit', '-qam', 'replacement')
        replacement = workflow.git(self.source, 'rev-parse', 'HEAD')
        self.git(self.repo, 'fetch', str(self.source), replacement)
        self.git(self.repo, 'replace', self.sha, replacement)
        self.assertEqual(workflow.provenance(self.manifest)['agent']['tree'], tree)
        workflow.canary.git_identity(self.repo, self.sha, workflow.git_env())
        self.git(self.repo, 'config', 'include.path', str(self.root / 'private-config'))
        with self.assertRaisesRegex(RuntimeError, 'Git configuration'):
            workflow.provenance(self.manifest)

    def test_contained_probe_denies_baseline_write_with_isolated_mode(self):
        from test_candidate_canary import SYSTEM_PYTHON, SYSTEM_RUNTIME
        home = self.root / 'probe'; home.mkdir()
        sentinel = self.repo / 'file.txt'
        code = ('import pathlib,sys,os\nassert sys.dont_write_bytecode\n'
                'assert "FAKE_PROVIDER_SECRET" not in os.environ\n'
                f'p=pathlib.Path({str(sentinel)!r})\n'
                'try: p.write_text("forbidden")\n'
                'except PermissionError: print("write_denied")\n'
                'else: raise RuntimeError("write escaped")\n')
        with mock.patch.dict(os.environ, FAKE_PROVIDER_SECRET='fixture-only'):
            result = workflow.contained_command([SYSTEM_PYTHON, '-I', '-B', '-c', code],
                                                home, [Path(SYSTEM_RUNTIME), self.repo])
        self.assertEqual(result, 'write_denied')
        self.assertEqual(sentinel.read_text(), 'approved\n')

    def test_inventory_detects_new_bytecode(self):
        before = workflow.launcher.inventory(self.repo)
        (self.repo / '__pycache__').mkdir()
        (self.repo / '__pycache__/unexpected.pyc').write_bytes(b'fixture')
        self.assertNotEqual(before, workflow.launcher.inventory(self.repo))

    def test_verify_rejects_different_requested_commit(self):
        cfg = {'output': str(self.root), 'agent_commit': '3' * 40, 'webui_commit': self.sha}
        with mock.patch.object(workflow.launcher, 'load_manifest', return_value=self.manifest):
            with self.assertRaisesRegex(RuntimeError, 'requested commit'):
                workflow.verify(cfg)


if __name__ == '__main__':
    unittest.main()
