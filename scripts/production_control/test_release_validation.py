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


if __name__ == '__main__':
    unittest.main()
