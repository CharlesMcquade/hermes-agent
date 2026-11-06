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

    def test_pending_check_is_explicit_readonly_and_separate_from_canary(self):
        self.assertEqual(workflow.pending_check({})['status'], 'pending_gate_not_checked')
        base = self.root/'base'; base.mkdir()
        baseline = base/'production-release.json'; baseline.write_text('old')
        output = self.root/'candidate'; output.mkdir(); (output/'release.json').write_text('new')
        cfg = dict(baseline=str(baseline), output=str(output), controls=str(self.root/'controls'),
                   scratch=str(self.root), control_refresh_sha256='a'*64)
        for rc, payload, expected in (
            (2, {'status':'blocked','installed_protocol':'reviewed_installed_protocol_admitted'}, 'blocked'),
            (0, {'pending_gate':{'status':'checked_not_staged'},'app_canary':'separate_gate_not_run'}, 'checked_not_staged'),
            (0, {'status':'passed'}, 'blocked')):
            with mock.patch.object(workflow.subprocess, 'run', return_value=subprocess.CompletedProcess([],rc,json.dumps(payload),'')) as run:
                result = workflow.pending_check(cfg)
            self.assertEqual(result['status'], expected)
            argv=run.call_args.args[0]
            self.assertIn('--check',argv)
            self.assertNotIn('--prepare',argv)
            self.assertNotIn('--select',argv)
            self.assertNotIn('--approve-prepare',argv)
            self.assertEqual(argv[1:3],['-I','-B'])
            self.assertEqual(set(run.call_args.kwargs['env']),{'HOME','TMPDIR','PATH'})

    def git(self, repo, *args):
        return subprocess.run(['/usr/bin/git', '-C', str(repo), *args],
                              capture_output=True, check=True)

    def test_genuine_snapshot_and_commit_objects(self):
        result = workflow.provenance(self.manifest)
        self.assertEqual(result['agent']['commit'], self.sha)
        self.assertTrue((self.repo / '.git/objects').is_dir())

    def test_snapshot_preserves_raw_blobs_with_crlf_attributes(self):
        (self.source / '.gitattributes').write_text('*.ps1 text eol=crlf\n')
        (self.source / 'activate.ps1').write_bytes(b'Write-Output fixture\n')
        self.git(self.source, 'add', '.')
        self.git(self.source, 'commit', '-qm', 'crlf checkout fixture')
        sha = workflow.git(self.source, 'rev-parse', 'HEAD')
        dest = self.root / 'crlf-snapshot'
        workflow.snapshot(self.source, sha, dest)
        self.assertEqual((dest / 'activate.ps1').read_bytes(), b'Write-Output fixture\n')
        self.assertFalse((dest / '.git/info/attributes').exists())
        workflow.canary.tracked_bytes(dest, sha, workflow.git_env())

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

    def _make_runtime(self, runtime):
        """A relocatable base python + venv under `runtime`, built like production's."""
        import shutil
        base = runtime / 'python'
        from test_candidate_canary import SYSTEM_PYTHON
        source_base = subprocess.check_output([SYSTEM_PYTHON, '-B', '-s', '-c',
            'import sys; print(sys.base_prefix)'], env=workflow.isolated_env(self.root), text=True).strip()
        shutil.copytree(Path(source_base).resolve(), base, symlinks=True,
                        ignore=lambda d, names: [n for n in names if n == 'site-packages' or n == '__pycache__' or n.endswith('.pyc')])
        home = self.root / ('bootstrap-' + runtime.parent.name); home.mkdir()
        workflow.contained_command([str(base / 'bin/python3'), '-B', '-s', '-m', 'venv',
                                    '--without-pip', str(runtime / 'venv')], home, [runtime],
                                   writes=[runtime], exec_roots=[runtime])
        return runtime / 'venv/bin/python'

    def _build_fixture(self):
        """Baseline release 'old' + build config for 'new'; returns (cfg, old, sha)."""
        old = self.root / 'old'
        runtime = old / 'runtime'
        self._make_runtime(runtime)
        for package in ('hermes_cli', 'gateway'):
            (self.source / package).mkdir()
            (self.source / package / '__init__.py').touch()
        identity = ('import subprocess\nfrom pathlib import Path\n'
                    'def sha(): return subprocess.check_output(["git", "-C", '
                    'str(Path(__file__).resolve().parents[1]), "rev-parse", "HEAD"], text=True).strip()\n')
        (self.source / 'hermes_cli/main.py').write_text(identity +
            'def _read_git_revision_fingerprint(p): return "git:HEAD:" + sha()\n')
        (self.source / 'hermes_cli/version_info.py').write_text(identity +
            'def get_code_identity(): return {"sha":sha()}\n')
        (self.source / 'gateway/code_skew.py').write_text(identity +
            'def current_code_sha(): return sha()\n')
        (self.source / 'hermes_cli/_launchers.py').write_text(
            'def ensure_install_launchers(repo, destination):\n'
            '    (destination / "fixture").write_text("fixture launcher")\n\n'
            'def mint_launcher(name, repo, destination, python, site_packages):\n'
            '    assert name == "hermes" and destination == python.parent\n'
            '    assert site_packages is None\n'
            '    target = destination / name\n'
            '    target.write_text("#!/bin/sh\\n# repo: " + str(repo) + "\\nexec " + str(python) + " -m hermes_cli.main \\\"$@\\\"\\n")\n'
            '    target.chmod(0o755)\n'
            '    return target\n')
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
        cfg = dict(baseline=str(baseline), output=str(self.root / 'new'), scratch=str(self.root / 'scratch'),
                   agent_repo=str(self.source), webui_repo=str(self.source), agent_commit=sha, webui_commit=sha)
        return cfg, old, sha

    def test_build_seals_exact_fixture_and_preserves_baseline(self):
        cfg, old, sha = self._build_fixture()
        before = workflow.canary.inventory(old)
        result = workflow.build(cfg)
        self.assertEqual(result['status'], 'static_verified_not_deployed')
        self.assertEqual(workflow.canary.inventory(old), before)
        console = self.root / 'new/runtime/venv/bin/hermes'
        self.assertTrue(console.is_file(), 'runtime-local console must exist before sealing')
        self.assertTrue(os.access(console, os.X_OK), 'runtime-local console must be executable')
        workflow.require_sealed(self.root / 'new')
        self.assertEqual(workflow.verify(cfg)['manifest_sha256'], result['manifest_sha256'])
        built = json.loads((Path(cfg["output"]) / "release.json").read_bytes())
        # Without runtime_source the runtime is inherited from the baseline, and says so.
        self.assertEqual(built['runtime']['mode'], 'inherited')
        self.assertEqual(built['runtime']['source'], str(old / 'runtime/venv/bin/python'))
        self.assertRegex(built['runtime']['python_version'], r'^\d+\.\d+\.\d+')
        console = self.root / 'new/runtime/venv/bin/hermes'
        self.assertTrue(console.is_file())
        self.assertEqual(console.stat().st_mode & 0o111, 0o111)
        contents = console.read_text()
        self.assertIn(str(self.root / 'new/agent'), contents)
        self.assertIn(str(self.root / 'new/runtime/venv/bin/python'), contents)
        webui = built["services"]["webui"]
        self.assertEqual(webui["env"]["HERMES_WEBUI_PYTHON"], webui["argv"][0])
        # Exercise the actual launcher merge: mutable runtime.env cannot redirect CLI.
        import types
        dotenv = types.ModuleType("dotenv")
        dotenv.dotenv_values = lambda *a, **kw: {"HERMES_WEBUI_PYTHON": "/fixture/wrong-python"}
        webui["env_files"] = ["/fixture/runtime.env"]
        with mock.patch.dict(os.environ, {"HERMES_WEBUI_PYTHON": "/fixture/inherited-python"}, clear=True), \
             mock.patch.dict(sys.modules, {"dotenv": dotenv}), \
             mock.patch.object(sys, "argv", ["entry", json.dumps(webui)]), \
             mock.patch.object(os, "chdir"), mock.patch.object(os, "execve") as execute:
            exec(workflow.launcher._ENTRY, {})
            self.assertEqual(execute.call_args.args[2]["HERMES_WEBUI_PYTHON"], webui["argv"][0])

    def test_runtime_source_builds_from_genesis_not_baseline(self):
        cfg, old, sha = self._build_fixture()
        genesis = self.root / 'genesis'
        genesis_python = self._make_runtime(genesis)
        # Only the genesis venv carries this marker distribution; the baseline does not.
        purelib = next((genesis / 'venv/lib').glob('python*/site-packages'))
        (purelib / 'genesis_marker-1.0.dist-info').mkdir()
        (purelib / 'genesis_marker-1.0.dist-info/METADATA').write_text('Name: genesis-marker\nVersion: 1.0\n')
        (purelib / 'genesis_marker.py').write_text('MARK = 1\n')
        cfg.update(runtime_source=str(genesis_python), runtime_source_root=str(genesis))
        before = workflow.canary.inventory(old)
        result = workflow.build(cfg)
        self.assertEqual(result['status'], 'static_verified_not_deployed')
        self.assertEqual(workflow.canary.inventory(old), before)
        built = json.loads((self.root / 'new/release.json').read_bytes())
        self.assertEqual(built['runtime']['mode'], 'genesis')
        self.assertEqual(built['runtime']['source'], str(genesis_python))
        self.assertIn('genesis-marker', workflow.installed_distributions(self.root / 'new/runtime'))
        self.assertNotIn('genesis-marker', workflow.installed_distributions(old / 'runtime'))
        workflow.require_sealed(self.root / 'new')
        self.assertEqual(workflow.verify(cfg)['manifest_sha256'], result['manifest_sha256'])

    def test_runtime_source_config_rejections(self):
        cfg = {k: str(self.root / k) for k in ('baseline', 'output', 'scratch', 'agent_repo', 'webui_repo')}
        cfg.update(agent_commit=self.sha, webui_commit=self.sha)
        genesis = self.root / 'genesis'
        (genesis / 'venv/bin').mkdir(parents=True)
        (genesis / 'venv/bin/python').touch()
        path = self.root / 'config.json'
        cases = {
            'root without python': {'runtime_source_root': str(genesis)},
            'python without root': {'runtime_source': str(genesis / 'venv/bin/python')},
            'python escapes root': {'runtime_source': str(genesis / 'venv/bin/python'),
                                    'runtime_source_root': str(self.root / 'elsewhere')},
            'not a venv python': {'runtime_source': str(genesis / 'venv'),
                                  'runtime_source_root': str(genesis)},
            'scratch inside genesis': {'runtime_source': str(genesis / 'venv/bin/python'),
                                       'runtime_source_root': str(genesis),
                                       'scratch': str(genesis / 'scratch')},
            'output inside genesis': {'runtime_source': str(genesis / 'venv/bin/python'),
                                      'runtime_source_root': str(genesis),
                                      'output': str(genesis / 'new')},
        }
        for name, updates in cases.items():
            with self.subTest(case=name):
                path.write_text(json.dumps(dict(cfg, **updates)))
                with self.assertRaises(RuntimeError):
                    workflow.config_read(path)
        path.write_text(json.dumps(dict(cfg, runtime_source=str(genesis / 'venv/bin/python'),
                                        runtime_source_root=str(genesis))))
        self.assertEqual(Path(workflow.config_read(path)['runtime_source_root']), genesis.resolve())

    def test_genesis_root_may_not_be_a_release_or_state(self):
        cfg, old, sha = self._build_fixture()
        baseline = workflow.launcher.load_manifest(Path(cfg['baseline']))
        for bad in (old / 'runtime', Path(baseline['state_dir']) / 'tools', Path(baseline['state_dir'])):
            with self.subTest(root=str(bad)):
                with self.assertRaisesRegex(RuntimeError, 'release tree or real state'):
                    workflow.check_placement(dict(cfg, runtime_source=str(bad / 'venv/bin/python'),
                                                  runtime_source_root=str(bad)), baseline)

    def test_marker_evaluation_matches_pep508_for_upstream_forms(self):
        env = workflow.marker_environment('3.14.9')
        self.assertTrue(workflow.evaluate_marker("python_version >= '3.14'", env))
        self.assertFalse(workflow.evaluate_marker("python_version >= '3.14'", workflow.marker_environment('3.11.16')))
        self.assertTrue(workflow.evaluate_marker("python_version >= '3.9'", workflow.marker_environment('3.11.16')),
                        'version comparison must be numeric, not lexical')
        self.assertEqual(workflow.evaluate_marker("sys_platform == 'win32' and python_version >= '3.14'", env),
                         sys.platform == 'win32')
        self.assertTrue(workflow.evaluate_marker(
            "((sys_platform == 'darwin' and platform_machine == 'arm64') or (sys_platform == 'linux' "
            "and platform_machine == 'x86_64' and 'android' not in platform_release)) and python_version >= '3.14'",
            dict(env, sys_platform='darwin', platform_machine='arm64')))
        self.assertFalse(workflow.evaluate_marker("extra == 'dev'", env))
        for hostile in ("__import__('os')", "python_version.__class__", "open('x')", "python_version == '3.14' or 1"):
            with self.subTest(marker=hostile):
                with self.assertRaises(RuntimeError):
                    workflow.evaluate_marker(hostile, env)

    def _drift_root(self, deps, requirements, installed, python='3.11.16', name='drift'):
        root = self.root / name
        (root / 'agent/pm').mkdir(parents=True)
        (root / 'webui').mkdir()
        purelib = root / 'runtime/venv/lib/python3.11/site-packages'
        purelib.mkdir(parents=True)
        (root / 'runtime/venv/pyvenv.cfg').write_text('home = /x\nversion = %s\n' % python)
        (root / 'agent/pyproject.toml').write_text(
            '[project]\nname = "x"\ndependencies = [%s]\n' % ', '.join(json.dumps(d) for d in deps))
        (root / 'webui/requirements.txt').write_text(requirements)
        (root / 'agent/pm/lock.json').write_text(json.dumps(
            {'packages': {'uv': {'version': '0.13.5'}, 'python': {'version': '3.14.9+20261021'}}}))
        for name in installed:
            info = purelib / (name.replace('-', '_') + '-1.0.dist-info'); info.mkdir()
            (info / 'METADATA').write_text('Metadata-Version: 2.1\nName: %s\nVersion: 1.0\n' % name)
        return root

    def test_drift_gate_evaluates_markers_at_target_python_and_reads_only(self):
        deps = ["PyYAML==6.0; python_version >= '3.14'", "pywin32; sys_platform == 'win32' and python_version >= '3.14'",
                "Pillow-HEIF==1.0; python_version >= '3.14'"]
        root = self._drift_root(deps, '# comment\npyyaml>=6.0\ncryptography>=42.0\n-r other.txt\n',
                                installed=['PyYAML', 'cryptography'])
        facts = self.root / 'facts.json'
        facts.write_text(json.dumps({'packages': {'uv': {'version': '0.13.5'}, 'python': {'version': '3.14.9+20261021'}}}))
        before = workflow.canary.inventory(root)
        report = workflow.runtime_dependency_drift(root, facts)
        self.assertEqual(workflow.canary.inventory(root), before, 'drift gate wrote into the release')
        self.assertEqual(report['status'], 'runtime_deps_drift')
        self.assertEqual(report['missing'], ['pillow-heif'])   # normalized; win32-only dep ignored here
        self.assertEqual(report['marker_python'], '3.14.9')
        self.assertEqual(report['runtime_python'], '3.11.16')
        self.assertEqual(report['pm']['status'], 'matched')
        self.assertTrue(any('below the dependency target' in w for w in report['warnings']))
        facts.write_text(json.dumps({'packages': {'uv': {'version': '0.13.4'}, 'python': {'version': '3.14.9+20261021'}}}))
        behind = workflow.runtime_dependency_drift(root, facts)
        self.assertEqual(behind['pm']['status'], 'store_behind_lock')
        self.assertTrue(any('pre-seed' in w for w in behind['warnings']))
        clean = self._drift_root(deps, 'pyyaml\n', installed=['pyyaml', 'pillow_heif'], name='clean')
        self.assertEqual(workflow.runtime_dependency_drift(clean, facts)['status'], 'clean')

    def test_prepare_blocks_on_unaccepted_drift_only(self):
        report = {'missing': ['pillow-heif', 'tomli-w']}
        self.assertEqual(workflow.unaccepted_drift(dict(report), {}), ['pillow-heif', 'tomli-w'])
        self.assertEqual(workflow.unaccepted_drift(dict(report), {'accept_runtime_drift': ['Pillow_HEIF', 'tomli-w']}), [])
        partial = dict(report)
        self.assertEqual(workflow.unaccepted_drift(partial, {'accept_runtime_drift': ['pillow-heif']}), ['tomli-w'])
        self.assertEqual(partial['missing'], ['pillow-heif', 'tomli-w'], 'acceptance must not hide the gap')
        self.assertEqual(partial['accepted'], ['pillow-heif'])


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
