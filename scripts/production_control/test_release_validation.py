"""Tests for bounded, exact-delta release validation."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import release_validation as validation


class ReleaseValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repos = {}
        self.commits = {}
        for name in ('agent', 'webui'):
            repo = self.root / name
            repo.mkdir()
            self.git(repo, 'init', '-q')
            self.git(repo, 'config', 'user.name', 'Fixture')
            self.git(repo, 'config', 'user.email', 'fixture@example.invalid')
            (repo / 'app.py').write_text('VALUE = 1\n')
            (repo / 'README.md').write_text('fixture\n')
            (repo / 'tests').mkdir()
            (repo / 'tests/test_app.py').write_text('def test_app(): pass\n')
            (repo / 'tests/test_neighbor.py').write_text('def test_neighbor(): pass\n')
            (repo / 'scripts').mkdir()
            (repo / ('scripts/run_tests.sh' if name == 'agent' else 'scripts/test.sh')).write_text('#!/bin/sh\n')
            self.git(repo, 'add', '.')
            self.git(repo, 'commit', '-qm', 'base')
            base = self.rev(repo, 'HEAD')
            (repo / 'app.py').write_text('VALUE = 2\n')
            (repo / 'tests/test_app.py').write_text('def test_app(): assert True\n')
            self.git(repo, 'add', '.')
            self.git(repo, 'commit', '-qm', 'candidate')
            candidate = self.rev(repo, 'HEAD')
            self.repos[name] = repo
            self.commits[name] = (base, candidate)
        self.baseline = self.root / 'baseline.json'
        self.baseline.write_text(json.dumps({'source_commits': {n: c[0] for n, c in self.commits.items()}}))
        self.cfg = {
            'baseline': str(self.baseline),
            'agent_repo': str(self.repos['agent']), 'webui_repo': str(self.repos['webui']),
            'agent_commit': self.commits['agent'][1], 'webui_commit': self.commits['webui'][1],
            'validation': {'agent': {'tests': ['tests/test_neighbor.py']}},
        }

    @staticmethod
    def git(repo, *args):
        return subprocess.run(['git', '-C', str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()

    def rev(self, repo, ref):
        return self.git(repo, 'rev-parse', ref)

    def test_plan_selects_changed_and_neighboring_tests_only(self):
        base = self.commits['webui'][0]
        self.git(self.repos['webui'], 'reset', '--hard', '-q', base)
        self.cfg['webui_commit'] = base
        plan = validation.validation_plan(self.cfg)
        self.assertEqual(plan['repositories']['agent']['tests'],
                         ['tests/test_app.py', 'tests/test_neighbor.py'])
        self.assertEqual(plan['repositories']['agent']['changed_files'], ['app.py', 'tests/test_app.py'])
        self.assertEqual(plan['repositories']['webui']['status'], 'unchanged')

    def test_docs_only_and_unchanged_repos_need_no_test_list(self):
        for name, (base, candidate) in self.commits.items():
            self.git(self.repos[name], 'reset', '--hard', '-q', base)
            self.cfg[name + '_commit'] = base
        self.cfg['validation'] = {}
        plan = validation.validation_plan(self.cfg)
        self.assertTrue(all(item['status'] == 'unchanged' for item in plan['repositories'].values()))

    def test_non_doc_change_without_tests_fails_closed(self):
        self.cfg['validation'] = {}
        with self.assertRaisesRegex(RuntimeError, 'focused tests required'):
            validation.validation_plan(self.cfg)
        self.assertFalse(validation.documentation_only(['requirements.txt']))

    def test_deleted_changed_test_is_not_executed(self):
        base = self.commits['webui'][0]
        self.git(self.repos['webui'], 'reset', '--hard', '-q', base)
        self.cfg['webui_commit'] = base
        self.git(self.repos['agent'], 'rm', '-q', 'tests/test_app.py')
        self.git(self.repos['agent'], 'commit', '-qm', 'remove a test')
        self.cfg['agent_commit'] = self.rev(self.repos['agent'], 'HEAD')
        plan = validation.validation_plan(self.cfg)
        self.assertEqual(plan['repositories']['agent']['tests'], ['tests/test_neighbor.py'])
        self.assertIn('tests/test_app.py', plan['repositories']['agent']['changed_files'])

    def _real_upstream_merge(self, name):
        repo = self.repos[name]
        other = 'webui' if name == 'agent' else 'agent'
        # This test isolates one repository's discovery mode. The sibling is an
        # unchanged repository, as in the existing execution tests.
        self.cfg[other + '_commit'] = self.commits[other][0]
        production = self.commits[name][0]
        self.git(repo, 'reset', '--hard', '-q', production)
        mainline = self.git(repo, 'branch', '--show-current')
        self.git(repo, 'checkout', '-b', 'validation-upstream')
        (repo / 'tests/test_inherited.py').write_text('def test_inherited(): pass\n')
        self.git(repo, 'add', 'tests/test_inherited.py')
        self.git(repo, 'commit', '-qm', 'upstream test')
        upstream = self.rev(repo, 'HEAD')
        self.git(repo, 'checkout', mainline)
        self.git(repo, 'checkout', '-b', 'validation-overlay')
        (repo / 'app.py').write_text('VALUE = "overlay"\n')
        (repo / 'tests/test_overlay.py').write_text('def test_overlay(): pass\n')
        self.git(repo, 'add', 'app.py', 'tests/test_overlay.py')
        self.git(repo, 'commit', '-qm', 'overlay behavior')
        self.git(repo, 'merge', '--no-ff', '-qm', 'merge upstream', 'validation-upstream')
        candidate = self.rev(repo, 'HEAD')
        self.cfg[name + '_commit'] = candidate
        self.cfg['validation'][name] = {
            'tests': ['tests/test_neighbor.py'],
            'TODO': ['helper-owned-metadata'],
        }
        return repo, production, upstream, candidate

    def test_missing_or_out_of_tree_test_is_rejected(self):
        self.cfg['validation']['agent']['tests'] = ['tests/not_here.py']
        with self.assertRaisesRegex(RuntimeError, 'does not exist'):
            validation.validation_plan(self.cfg)
        self.cfg['validation']['agent']['tests'] = ['../outside.py']
        with self.assertRaisesRegex(RuntimeError, 'relative test'):
            validation.validation_plan(self.cfg)

    def test_execution_binds_clean_exact_head_and_writes_receipt(self):
        # WebUI is made unchanged so only one canonical runner executes.
        base = self.commits['webui'][0]
        self.git(self.repos['webui'], 'reset', '--hard', '-q', base)
        self.cfg['webui_commit'] = base
        plan = validation.validation_plan(self.cfg)
        completed = subprocess.CompletedProcess([], 0, '', '')
        real_run = subprocess.run
        def run_test_or_git(argv, *args, **kwargs):
            if argv[0].startswith('scripts/'):
                return completed
            return real_run(argv, *args, **kwargs)
        with mock.patch.object(validation.subprocess, 'run', side_effect=run_test_or_git) as run:
            report = validation.execute_plan(self.cfg, plan, self.root / 'evidence')
        test_calls = [call for call in run.call_args_list if call.args[0][0].startswith('scripts/')]
        self.assertEqual(len(test_calls), 1)
        self.assertEqual(report['status'], 'passed')
        argv = test_calls[0].args[0]
        self.assertEqual(argv[:2], ['scripts/run_tests.sh', 'tests/test_app.py'])
        self.assertEqual(argv[2:], ['tests/test_neighbor.py'])
        self.assertTrue((self.root / 'evidence/report.json').is_file())
        self.assertEqual(json.loads((self.root / 'evidence/report.json').read_text())['source_commits']['agent'],
                         self.commits['agent'][1])

    def test_agent_explicit_interpreter_is_recorded_and_passed_to_runner(self):
        base = self.commits['webui'][0]
        self.git(self.repos['webui'], 'reset', '--hard', '-q', base)
        self.cfg['webui_commit'] = base
        executable = self.root / 'test-python'
        # Exercised only as a path/argv fixture; the canonical runner performs
        # the actual interpreter's pytest capability check before executing.
        executable.write_text('# Only an executable-path fixture; not executed.\n')
        executable.chmod(0o700)
        self.cfg['validation']['agent']['python'] = str(executable)
        plan = validation.validation_plan(self.cfg)
        self.assertEqual(plan['repositories']['agent']['test_python'], str(executable))
        self.assertEqual(plan['repositories']['agent']['tests'],
                         ['tests/test_app.py', 'tests/test_neighbor.py'])
        completed = subprocess.CompletedProcess([], 0, '', '')
        real_run = subprocess.run
        def run_test_or_git(argv, *args, **kwargs):
            if argv[0].startswith('scripts/'):
                return completed
            return real_run(argv, *args, **kwargs)
        with mock.patch.object(validation.subprocess, 'run', side_effect=run_test_or_git) as run:
            report = validation.execute_plan(self.cfg, plan, self.root / 'evidence-explicit-python')
        self.assertEqual(report['status'], 'passed')
        calls = [call for call in run.call_args_list
                 if call.args[0][0].startswith('scripts/run_tests.sh')]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].kwargs['env'].get('HERMES_PYTHON'), str(executable))
        self.assertNotIn('HERMES_RUNTIME_DIR', calls[0].kwargs['env'])
        self.assertNotIn('UV_PYTHON_INSTALL_DIR', calls[0].kwargs['env'])

    def test_explicit_interpreter_requires_an_absolute_executable_path(self):
        for value in ('relative-python', ['not', 'a', 'path']):
            with self.subTest(value=value):
                self.cfg['validation']['agent']['python'] = value
                pattern = 'interpreter path' if not isinstance(value, str) else 'absolute interpreter path'
                with self.assertRaisesRegex(RuntimeError, pattern):
                    validation.validation_plan(self.cfg)
        missing = self.root / 'missing-python'
        self.cfg['validation']['agent']['python'] = str(missing)
        with self.assertRaisesRegex(RuntimeError, 'executable file'):
            validation.validation_plan(self.cfg)
        missing.write_text('Not an executable interpreter.\n')
        with self.assertRaisesRegex(RuntimeError, 'executable file'):
            validation.validation_plan(self.cfg)

    def test_execution_fails_before_runner_on_dirty_or_wrong_head(self):
        base = self.commits['webui'][0]
        self.git(self.repos['webui'], 'reset', '--hard', '-q', base)
        self.cfg['webui_commit'] = base
        (self.repos['agent'] / 'app.py').write_text('dirty\n')
        plan = validation.validation_plan(self.cfg)
        real_run = subprocess.run
        def fail_if_test_invoked(argv, *args, **kwargs):
            if argv[0].startswith('scripts/'):
                raise AssertionError('test runner must not execute')
            return real_run(argv, *args, **kwargs)
        with mock.patch.object(validation.subprocess, 'run', side_effect=fail_if_test_invoked):
            with self.assertRaisesRegex(RuntimeError, 'clean checkout'):
                validation.execute_plan(self.cfg, plan, self.root / 'evidence-dirty')

    def test_merge_discovery_base_is_bound_to_real_upstream_parent(self):
        for name in ('agent', 'webui'):
            with self.subTest(repo=name):
                repo, production, upstream, candidate = self._real_upstream_merge(name)
                broad = validation.validation_plan(self.cfg)
                self.assertEqual(broad['repositories'][name]['tests'], [
                    'tests/test_inherited.py', 'tests/test_neighbor.py', 'tests/test_overlay.py'])
                self.assertNotIn('test_discovery_base_commit', broad['repositories'][name])
                self.cfg['validation'][name]['test_discovery_base_commit'] = upstream
                plan = validation.validation_plan(self.cfg)
                entry = plan['repositories'][name]
                self.assertEqual(entry['tests'], ['tests/test_neighbor.py', 'tests/test_overlay.py'])
                self.assertEqual(entry['automatic_test_count'], 1)
                self.assertEqual(entry['production_delta_automatic_test_count'], 2)
                self.assertEqual(entry['changed_count'], 3)
                self.assertEqual(entry['test_discovery_base_commit'], upstream)
                self.assertEqual(self.cfg['validation'][name]['TODO'], ['helper-owned-metadata'])

    def test_merge_discovery_base_rejects_non_merge_parent_and_bad_sha(self):
        repo, production, upstream, candidate = self._real_upstream_merge('agent')
        self.cfg['validation']['agent']['test_discovery_base_commit'] = self.rev(repo, 'HEAD^1')
        with self.assertRaisesRegex(RuntimeError, 'second parent of a first-parent merge'):
            validation.validation_plan(self.cfg)
        self.cfg['validation']['agent']['test_discovery_base_commit'] = 'not-a-sha'
        with self.assertRaisesRegex(RuntimeError, '40 lowercase hexadecimal'):
            validation.validation_plan(self.cfg)

    def test_webui_environment_passes_real_playwright_cache_without_leaking_home(self):
        evidence = self.root / 'evidence'
        evidence.mkdir()
        cache = self.root / 'real-home/Library/Caches/ms-playwright'
        cache.mkdir(parents=True)
        with mock.patch.object(validation, 'playwright_browsers_path', return_value=str(cache)):
            env = validation.test_environment('webui', self.cfg, evidence)
        self.assertEqual(env['PLAYWRIGHT_BROWSERS_PATH'], str(cache))
        self.assertEqual(env['HOME'], str(evidence / 'home-webui'))
        agent_evidence = self.root / 'evidence-agent'
        agent_evidence.mkdir()
        self.assertNotIn('PLAYWRIGHT_BROWSERS_PATH',
                         validation.test_environment('agent', self.cfg, agent_evidence))
        self.assertIsNone(validation.playwright_browsers_path(self.root / 'no-such-home'))
        self.assertEqual(validation.playwright_browsers_path(self.root / 'real-home'), str(cache))


if __name__ == '__main__':
    unittest.main()
