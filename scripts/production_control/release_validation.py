#!/usr/bin/env python3
"""Run a bounded, exact-delta validation set for a frozen release candidate.

Full upstream suites remain available as explicit diagnostics. This module never
selects, installs, or restarts anything and never schedules remote compute.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path, PurePosixPath
import subprocess
import sys
import time
from typing import Any

SCHEMA_VERSION = 1
REPOSITORIES = ('agent', 'webui')
RUNNERS = {'agent': 'scripts/run_tests.sh', 'webui': 'scripts/test.sh'}


def encoded(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_output(repo: Path, *args: str) -> str:
    env = {
        'PATH': '/usr/bin:/bin', 'HOME': '/dev/null',
        'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
        'GIT_OPTIONAL_LOCKS': '0', 'GIT_NO_REPLACE_OBJECTS': '1',
    }
    return subprocess.check_output(
        ['git', '-C', str(repo), *args], env=env, text=True,
        stderr=subprocess.STDOUT, timeout=60,
    ).strip()


def slug(path: str) -> str:
    return path.replace('/', '__')


def documentation_only(changed_files: list[str]) -> bool:
    if not changed_files:
        return True
    for value in changed_files:
        path = PurePosixPath(value)
        if path.parts[0] in ('docs', 'website'):
            continue
        if path.suffix.lower() in ('.md', '.rst'):
            continue
        return False
    return True


def valid_test_path(value: Any) -> str:
    if not isinstance(value, str):
        raise RuntimeError('Validation tests must be relative test paths')
    path = PurePosixPath(value)
    if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] != 'tests':
        raise RuntimeError('Validation tests must be relative test paths under tests/: ' + value)
    return path.as_posix()


_SHA = re.compile(r'[0-9a-f]{40}\Z')


def _upstream_merge_discovery_base(repo: Path, candidate: str, settings: dict[str, Any]) -> str | None:
    """Validate an explicitly reviewed upstream merge parent for test discovery.

    Production is the default comparison. This exception is only for a genuine
    merge whose first-parent history contains the named second parent; an arbitrary
    ancestor cannot be used to discard inherited test coverage.
    """
    value = settings.get('test_discovery_base_commit')
    if value is None:
        return None
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise RuntimeError('test_discovery_base_commit must be 40 lowercase hexadecimal characters')
    history = git_output(repo, 'log', '--first-parent', '--format=%H %P', candidate)
    for line in history.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[2] == value:
            return value
    raise RuntimeError(
        'test_discovery_base_commit must be the second parent of a first-parent merge '
        'in the candidate history'
    )


def _automatic_changed_tests(repo: Path, baseline: str, candidate: str) -> list[str]:
    present_at_candidate = git_output(
        repo, 'diff', '--name-only', '--diff-filter=ACMR', baseline, candidate,
    ).splitlines()
    return sorted(
        value for value in present_at_candidate
        if value.startswith('tests/') and value.endswith('.py')
        and PurePosixPath(value).name.startswith('test_')
    )


def validation_plan(cfg: dict[str, Any]) -> dict[str, Any]:
    baseline_path = Path(cfg['baseline'])
    baseline = json.loads(baseline_path.read_text())
    baseline_commits = baseline['source_commits']
    plan = {
        'schema_version': SCHEMA_VERSION,
        'baseline': str(baseline_path),
        'baseline_sha256': digest(baseline_path),
        'source_commits': {name: cfg[name + '_commit'] for name in REPOSITORIES},
        'repositories': {},
        'policy': 'exact-delta-and-neighbors; full-suite-opt-in; local-only',
    }
    settings = cfg.get('validation', {})
    if not isinstance(settings, dict):
        raise RuntimeError('validation must be an object keyed by agent/webui')
    for name in REPOSITORIES:
        repo = Path(cfg[name + '_repo'])
        base = baseline_commits[name]
        candidate = cfg[name + '_commit']
        if base == candidate:
            plan['repositories'][name] = {
                'status': 'unchanged', 'baseline_commit': base,
                'candidate_commit': candidate, 'changed_files': [], 'tests': [],
            }
            continue
        changed = git_output(repo, 'diff', '--name-only', base, candidate).splitlines()
        repo_settings = settings.get(name, {})
        if not isinstance(repo_settings, dict) or not isinstance(repo_settings.get('tests', []), list):
            raise RuntimeError(name + ' validation.tests must be a list')
        test_python = explicit_test_python(name, repo_settings)
        focused = [valid_test_path(value) for value in repo_settings.get('tests', [])]
        discovery_base = _upstream_merge_discovery_base(repo, candidate, repo_settings)
        production_changed_tests = _automatic_changed_tests(repo, base, candidate)
        if discovery_base is None:
            changed_tests = production_changed_tests
        else:
            changed_tests = _automatic_changed_tests(repo, discovery_base, candidate)
        tests = sorted(set(focused + changed_tests))
        application_changed = any(not value.startswith('tests/') for value in changed)
        if application_changed and not focused and not documentation_only(changed):
            raise RuntimeError(
                name + ': focused tests required for changed application files; '
                'name neighboring tests under validation.' + name + '.tests'
            )
        unknown = set(settings) - set(REPOSITORIES) - {'timeout_seconds'}
        if unknown:
            raise RuntimeError('Unknown validation config keys: ' + ', '.join(sorted(unknown)))
        for test in tests:
            try:
                git_output(repo, 'cat-file', '-e', candidate + ':' + test)
            except subprocess.CalledProcessError:
                raise RuntimeError(name + ' test does not exist at candidate commit: ' + test) from None
        plan['repositories'][name] = {
            'status': 'ready' if tests else 'documentation_only',
            'baseline_commit': base, 'candidate_commit': candidate,
            'changed_files': changed, 'changed_count': len(changed), 'tests': tests,
            'paired': bool(repo_settings.get('paired', False)),
        }
        if discovery_base is not None:
            plan['repositories'][name]['test_discovery_base_commit'] = discovery_base
            plan['repositories'][name]['automatic_test_count'] = len(changed_tests)
            plan['repositories'][name]['production_delta_automatic_test_count'] = len(production_changed_tests)
        if test_python:
            plan['repositories'][name]['test_python'] = test_python
    return plan


def explicit_test_python(name: str, settings: dict[str, Any]) -> str | None:
    value = settings.get('python')
    if value is None:
        return None
    if not isinstance(value, str):
        raise RuntimeError(name + ' validation.python must be an interpreter path')
    path = Path(value)
    if not path.is_absolute():
        raise RuntimeError(name + ' validation.python must be an absolute interpreter path')
    if not path.is_file() or not os.access(path, os.X_OK):
        raise RuntimeError(name + ' validation.python must be an executable file')
    return str(path)


def test_environment(name: str, cfg: dict[str, Any], evidence: Path) -> dict[str, str]:
    home = evidence / ('home-' + name)
    home.mkdir(mode=0o755)
    temp = evidence / ('tmp-' + name)
    temp.mkdir(mode=0o755)
    env = {
        'HOME': str(home), 'TMPDIR': str(temp),
        'PATH': os.pathsep.join((str(Path.home() / '.local/bin'), '/opt/homebrew/bin',
                                 '/usr/local/bin', '/Library/Developer/CommandLineTools/usr/bin',
                                 '/usr/bin', '/bin', '/usr/sbin', '/sbin')),
        'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
        'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1',
        'HERMES_HOME': str(home / '.hermes'),
        'HERMES_WEBUI_AUTO_INSTALL': '0', 'HERMES_WEBUI_FOREGROUND': '1',
    }
    if name == 'agent':
        test_python = explicit_test_python(name, cfg.get('validation', {}).get(name, {}))
        if test_python:
            env['HERMES_PYTHON'] = test_python
    paired = name == 'webui' and cfg.get('validation', {}).get(name, {}).get('paired', False)
    if paired:
        webui = Path(cfg['webui_repo']).resolve()
        agent = Path(cfg['agent_repo']).resolve()
        python = webui / '.venv/bin/python'
        if not python.is_file():
            raise RuntimeError('paired WebUI validation needs .venv/bin/python in webui_repo')
        env['PYTHONPATH'] = os.pathsep.join((str(webui), str(agent)))
        env['HERMES_WEBUI_AGENT_DIR'] = str(agent)
        env['HERMES_WEBUI_PYTHON'] = str(python)
    if name == 'webui':
        env['HERMES_WEBUI_STATE_DIR'] = str(evidence / 'webui-runtime-state')
        env['HERMES_WEBUI_TEST_STATE_DIR'] = str(evidence / 'webui-test-state')
    if not paired:
        env.pop('PYTHONPATH', None)
    return env


def execute_plan(cfg: dict[str, Any], plan: dict[str, Any], evidence: Path) -> dict[str, Any]:
    if plan['source_commits'] != {name: cfg[name + '_commit'] for name in REPOSITORIES}:
        raise RuntimeError('Validation plan does not match requested source commits')
    evidence.mkdir(parents=True, exist_ok=False)
    (evidence / 'plan.json').write_bytes(encoded(plan))
    report = dict(plan)
    report['started_at'] = time.time()
    report['status'] = 'passed'
    timeout = cfg.get('validation', {}).get('timeout_seconds', 600)
    if not isinstance(timeout, int) or not 1 <= timeout <= 900:
        raise RuntimeError('validation.timeout_seconds must be an integer from 1 to 900')
    for name in REPOSITORIES:
        item = report['repositories'][name]
        if item['status'] in ('unchanged', 'documentation_only'):
            item['returncode'] = None
            continue
        repo = Path(cfg[name + '_repo'])
        candidate = cfg[name + '_commit']
        if git_output(repo, 'rev-parse', 'HEAD') != candidate or git_output(repo, 'status', '--porcelain'):
            raise RuntimeError(name + ': validation needs a clean checkout at the exact candidate commit')
        runner = repo / RUNNERS[name]
        if not runner.is_file():
            raise RuntimeError(name + ': canonical test runner missing: ' + RUNNERS[name])
        argv = [RUNNERS[name], *item['tests']]
        log = evidence / (name + '.log')
        started = time.monotonic()
        item['command'] = argv
        item['log'] = str(log)
        try:
            with log.open('wb') as output:
                result = subprocess.run(
                    argv, cwd=repo, env=test_environment(name, cfg, evidence),
                    stdout=output, stderr=subprocess.STDOUT, timeout=timeout, check=False,
                )
            item['returncode'] = result.returncode
        except subprocess.TimeoutExpired:
            item['returncode'] = None
            item['status'] = 'timeout'
        item['duration_seconds'] = round(time.monotonic() - started, 3)
        item['log_sha256'] = digest(log)
        if item['returncode'] != 0:
            if item['status'] != 'timeout':
                item['status'] = 'failed'
            report['status'] = 'failed'
            report['failed_repository'] = name
            break
        item['status'] = 'passed'
    report['finished_at'] = time.time()
    report['total_tests_files'] = sum(
        len(item['tests']) for item in report['repositories'].values()
    )
    report['local_only'] = True
    report['remote_jobs_created'] = 0
    (evidence / 'report.json').write_bytes(encoded(report))
    return report


def validate(cfg: dict[str, Any], evidence: Path) -> dict[str, Any]:
    return execute_plan(cfg, validation_plan(cfg), evidence)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--plan-only', action='store_true')
    args = parser.parse_args()
    try:
        cfg = json.loads(args.config.read_text())
        plan = validation_plan(cfg)
        if args.plan_only:
            print(json.dumps(plan, indent=2, sort_keys=True))
            return 0
        evidence = args.evidence or Path(cfg['evidence_dir']) / ('validation-' + str(time.time_ns()))
        report = execute_plan(cfg, plan, evidence)
        summary = {key: value for key, value in report.items()
                   if key not in ('repositories', 'baseline', 'source_commits')}
        summary['repositories'] = {
            name: {key: value for key, value in item.items() if key != 'changed_files'}
            for name, item in report['repositories'].items()
        }
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0 if report['status'] == 'passed' else 1
    except Exception as exc:
        print(json.dumps({'status': 'NOT_VALIDATED', 'error': str(exc)}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
