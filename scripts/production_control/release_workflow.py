#!/usr/bin/env python3
"""Prepare and certify a frozen release; never restart production.

All machine-specific paths and exact commits come from an explicit JSON config.
Use a new output directory for each build. Verification never repairs sealed bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import production_launcher as launcher
import release_build
import candidate_canary as canary

SHA = re.compile(r"[0-9a-f]{40}\Z")
SAFE_PATH = '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def isolated_env(home, repos=()):
    return {'HOME': str(home), 'HERMES_HOME': str(home / 'agent-home'),
            'HERMES_BASE_HOME': str(home / 'agent-home'),
            'HERMES_WEBUI_STATE_DIR': str(home / 'webui-state'),
            'HERMES_CONFIG_PATH': str(home / 'agent-home/config.yaml'),
            'PATH': SAFE_PATH, 'TMPDIR': str(home), 'PYTHONDONTWRITEBYTECODE': '1',
            'PYTHONNOUSERSITE': '1', 'PYTHONSAFEPATH': '1',
            'PYTHONPATH': os.pathsep.join(map(str, repos)),
            'HERMES_WEBUI_AGENT_DIR': str(repos[-1]) if repos else '',
            'HERMES_WEBUI_AUTO_INSTALL': '0', 'HERMES_WEBUI_FOREGROUND': '1'}


def git_env():
    return {'PATH': '/usr/bin:/bin', 'HOME': '/dev/null',
            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
            'GIT_OPTIONAL_LOCKS': '0', 'GIT_NO_REPLACE_OBJECTS': '1',
            'PYTHONDONTWRITEBYTECODE': '1'}


def git(repo, *args):
    env = git_env()
    result = subprocess.run(canary.git_command(repo, *args),
                            env=env, capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise RuntimeError(f'Git validation failed: {args[0]} in {repo}')
    return result.stdout.strip()


def canonical_path(value, label):
    if not isinstance(value, str) or not value or '\x00' in value:
        raise RuntimeError(f'{label} must be a path string')
    path = Path(value)
    if not path.is_absolute() or '..' in path.parts or any(p.is_symlink() for p in (path, *path.parents)):
        raise RuntimeError(f'{label} must be an absolute non-symlink path')
    return path


def overlaps(a, b):
    return a.is_relative_to(b) or b.is_relative_to(a)


def validate_config_paths(cfg):
    paths = {k: canonical_path(cfg[k], k) for k in
             ('baseline', 'output', 'scratch', 'agent_repo', 'webui_repo')}
    for key in ('evidence_dir', 'controls'):
        if key in cfg:
            paths[key] = canonical_path(cfg[key], key)
    output = paths['output']
    for key, value in paths.items():
        if key != 'output' and overlaps(output, value):
            raise RuntimeError('output overlaps ' + key)
    for writable in ('scratch', 'evidence_dir'):
        if writable in paths:
            for protected in ('agent_repo', 'webui_repo', 'controls'):
                if protected in paths and overlaps(paths[writable], paths[protected]):
                    raise RuntimeError(writable + ' overlaps ' + protected)
            if paths['baseline'].is_relative_to(paths[writable]):
                raise RuntimeError(writable + ' contains baseline')
    tool_path = cfg.get('tool_path', SAFE_PATH)
    if not isinstance(tool_path, str):
        raise RuntimeError('tool_path must be a string')
    for entry in tool_path.split(os.pathsep):
        if not entry or not Path(entry).is_absolute() or '..' in Path(entry).parts or any(c in entry for c in '\x00\n\r'):
            raise RuntimeError('tool_path entries must be absolute paths')
        if entry not in SAFE_PATH.split(os.pathsep) and any((Path(entry) / name).exists() for name in ('python', 'python3')):
            raise RuntimeError('tool_path contains another Python runtime')


def config_read(path):
    cfg = json.loads(path.read_text())
    validate_config_paths(cfg)
    for key in ('agent_commit', 'webui_commit'):
        if not isinstance(cfg[key], str) or not SHA.fullmatch(cfg[key]):
            raise RuntimeError(f'{key} must be an exact lowercase 40-character commit')
    return cfg


def provenance(manifest):
    results = {}
    for name, item in manifest['services'].items():
        repo = Path(item['repo'])
        sha = manifest['source_commits'][name]
        if not SHA.fullmatch(sha) or item['commit'] != sha:
            raise RuntimeError(f'{name}: manifest commit disagreement')
        if not (repo / '.git').is_dir() or (repo / '.git').is_symlink():
            raise RuntimeError(f'{name}: standalone genuine Git metadata required')
        if (repo / '.git/objects/info/alternates').exists() or (repo / '.git/commondir').exists():
            raise RuntimeError(f'{name}: external Git object dependency')
        canary.validate_git_metadata(repo, git_env())
        if git(repo, 'rev-parse', '--verify', 'HEAD^{commit}') != sha:
            raise RuntimeError(f'{name}: Git HEAD disagrees with manifest')
        git(repo, 'fsck', '--full', '--no-reflogs')
        canary.tracked_bytes(repo, sha, git_env())
        results[name] = {'commit': sha, 'tree': git(repo, 'rev-parse', 'HEAD^{tree}')}
    return results


def contained_command(argv, home, reads, *, writes=(), exec_roots=(), env=None):
    """OS containment applies before interpreter startup, including .pth imports."""
    python = Path(argv[0])
    policy = canary.sandbox_policy(home, reads, 0, [python, python.resolve()])
    # Preparation/identity probes require no TCP listener, unlike the app canary.
    policy = '\n'.join(line for line in policy.splitlines()
                       if '(allow network-bind' not in line and '(allow network-inbound' not in line) + '\n'
    for path in writes:
        policy += '(allow file-write* (subpath ' + json.dumps(str(Path(path).resolve())) + '))\n'
    for path in exec_roots:
        policy += '(allow process-exec (subpath ' + json.dumps(str(Path(path).resolve())) + '))\n'
    policy_path = home / 'probe.sb'
    policy_path.write_text(policy)
    result = subprocess.run(['/usr/bin/sandbox-exec', '-f', str(policy_path), *argv],
                            cwd=home, env=env or isolated_env(home),
                            capture_output=True, text=True, timeout=180)
    if result.returncode:
        # Candidate output can include attempted secret reads. Do not echo it.
        raise RuntimeError('Contained interpreter probe failed')
    return result.stdout.strip()


def runtime_identity(manifest, scratch):
    item = manifest['services']['agent']
    repo = Path(item['repo'])
    with tempfile.TemporaryDirectory(prefix='release-identity-', dir=scratch) as temp:
        home = Path(temp)
        (home / 'agent-home').mkdir()
        code = ('import json; from hermes_cli.main import _read_git_revision_fingerprint; '
                'from gateway.code_skew import current_code_sha; from pathlib import Path; '
                'from hermes_cli.version_info import get_code_identity; '
                f'print(json.dumps({{"fingerprint":_read_git_revision_fingerprint(Path({str(repo)!r})),'
                '"runtime":current_code_sha(), "reported":get_code_identity()}))')
        reads = [repo, *[Path(r['root']) for r in item['runtimes']]]
        output = contained_command([item['argv'][0], '-B', '-s', '-c', code], home, reads,
                                   exec_roots=reads[1:], env=isolated_env(home, [repo]))
        data = json.loads(output.splitlines()[-1])
    if data['fingerprint'] != 'git:HEAD:' + item['commit']:
        raise RuntimeError('Actual agent fingerprint differs from exact commit')
    if data['runtime'] != item['commit'] or data['reported']['sha'] != item['commit']:
        raise RuntimeError('Actual gateway code SHA differs from manifest')
    return data


def release_layout(manifest, root):
    """Bound manifest-provided read/execute grants to one frozen artifact."""
    root = canonical_path(str(root), 'release root')
    if set(manifest['services']) != {'agent', 'webui'}:
        raise RuntimeError('Expected exactly agent and webui services')
    state = canonical_path(manifest['state_dir'], 'state_dir')
    if state.is_relative_to(root):
        raise RuntimeError('Release overlaps mutable state')
    runtime = root / 'runtime'
    for name, item in manifest['services'].items():
        if canonical_path(item['repo'], 'repo') != root / name:
            raise RuntimeError('Service repo escapes release layout')
        executable = Path(item['argv'][0])
        if executable != runtime / 'venv/bin/python' or not executable.resolve().is_relative_to(runtime):
            raise RuntimeError('Interpreter escapes private runtime')
        for descriptor in item.get('runtimes', []):
            if canonical_path(descriptor['root'], 'runtime') != runtime:
                raise RuntimeError('Runtime descriptor escapes release layout')
    if [r['root'] for r in manifest['services']['agent'].get('runtimes', [])] != [str(runtime)]:
        raise RuntimeError('Exactly one private agent runtime required')
    return runtime


def check_placement(cfg, baseline):
    validate_config_paths(cfg)
    old = Path(baseline['services']['agent']['repo']).parent
    release_layout(baseline, old)
    state = Path(baseline['state_dir'])
    for key in ('output', 'scratch', 'evidence_dir'):
        if key not in cfg:
            continue
        value = Path(cfg[key])
        if overlaps(value, old) or state.is_relative_to(value):
            raise RuntimeError(key + ' overlaps baseline or real state')
        if key in ('scratch', 'evidence_dir') and value.is_relative_to(state):
            if key != 'scratch' or not value.is_relative_to(state / 'cache/scratch'):
                raise RuntimeError(key + ' is inside application state, not dedicated scratch')


def require_sealed(root):
    for path in (root, *root.rglob('*')):
        if not path.is_symlink() and path.stat().st_mode & 0o222:
            raise RuntimeError('Release is not sealed read-only: ' + str(path))


def verify(cfg):
    path = Path(cfg['output']) / 'release.json'
    manifest = launcher.load_manifest(path)
    for name in ('agent', 'webui'):
        if manifest['source_commits'][name] != cfg[name + '_commit']:
            raise RuntimeError(f'{name}: manifest differs from requested commit')
    check_placement(cfg, launcher.load_manifest(Path(cfg['baseline'])))
    release_layout(manifest, Path(cfg['output']))
    require_sealed(Path(cfg['output']))
    before = canary.inventory(Path(cfg['output']))
    identity = provenance(manifest)
    for name in manifest['services']:
        launcher.validate(name, manifest['services'])
    runtime = runtime_identity(manifest, Path(cfg['scratch']))
    # Imports must not mutate the frozen payload after its inventory was sealed.
    for name in manifest['services']:
        launcher.validate(name, manifest['services'])
    if canary.inventory(Path(cfg['output'])) != before:
        raise RuntimeError('Release metadata or modes changed during verification')
    return {'status': 'static_verified_not_deployed', 'manifest': str(path),
            'manifest_sha256': digest(path), 'identity': identity, 'runtime': runtime}


def snapshot(source, sha, dest):
    if git(source, 'rev-parse', '--verify', sha + '^{commit}') != sha:
        raise RuntimeError('Source commit does not exist')
    dest.mkdir()
    git(dest, '-c', 'init.templateDir=', 'init', '--quiet')
    git(dest, 'fetch', '--quiet', '--depth=1', '--no-tags', str(source), sha)
    git(dest, 'checkout', '--quiet', '--detach', 'FETCH_HEAD')
    if git(dest, 'rev-parse', 'HEAD') != sha:
        raise RuntimeError('Snapshot identity mismatch')
    canary.tracked_bytes(dest, sha, git_env())


def rebase_paths(value: Any, old: str, new: str) -> Any:
    if isinstance(value, str):
        return ':'.join(new + part[len(old):] if part == old or part.startswith(old + '/')
                        else part for part in value.split(':'))
    if isinstance(value, list):
        return [rebase_paths(v, old, new) for v in value]
    if isinstance(value, dict):
        return {k: rebase_paths(v, old, new) for k, v in value.items()}
    return value


def build(cfg):
    baseline_path = Path(cfg['baseline'])
    baseline_bytes = baseline_path.read_bytes()
    baseline = launcher.load_manifest(baseline_path)
    old = Path(baseline['services']['agent']['repo']).parent
    check_placement(cfg, baseline)
    baseline_inventory = canary.inventory(old)
    for name in baseline['services']:
        launcher.validate(name, baseline['services'])
    root = Path(cfg['output'])
    old = Path(baseline['services']['agent']['repo']).parent
    scratch = Path(cfg['scratch'])
    scratch.mkdir(parents=True, exist_ok=True)
    root.mkdir(parents=True, exist_ok=False)
    for name in ('agent', 'webui'):
        snapshot(cfg[name + '_repo'], cfg[name + '_commit'], root / name)
    # Rebuild a relocatable private interpreter/dependency tree using the existing
    # known-working distribution. Never pip-install into a sealed runtime.
    with tempfile.TemporaryDirectory(prefix='release-build-', dir=scratch) as temp:
        home = Path(temp)
        baseline_runtime = old / 'runtime'
        def probe(argv, **kwargs):
            return contained_command(argv, home, [baseline_runtime, root / 'runtime'],
                                     writes=[root / 'runtime'], exec_roots=[baseline_runtime, root / 'runtime'])
        python = release_build.private_python(
            Path(baseline['services']['agent']['argv'][0]), root / 'runtime', runner=probe,
            source_root=baseline_runtime)
    manifest = rebase_paths(baseline, str(old), str(root))
    manifest.update(release_id=root.name, prepared_at=time.time(),
                    source_commits={name: cfg[name + '_commit'] for name in ('agent', 'webui')},
                    baseline_sha256=hashlib.sha256(baseline_bytes).hexdigest())
    for name, item in manifest['services'].items():
        item['commit'] = cfg[name + '_commit']
        item['version'] = git(root / name, 'describe', '--always')
        # No inherited stale release/development entries in subprocess PATH.
        item['env']['PATH'] = str(python.parent) + ':' + cfg.get('tool_path', SAFE_PATH)
    (root / 'agent/.bytecode-fingerprint').write_text('git:HEAD:' + cfg['agent_commit'])
    # Boot-time CLI exposure can create these. Materialize the exact files before
    # sealing, with a narrowly scoped function that writes only the NEW repo.
    (root / 'agent/.hermes/bin').mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='release-launchers-', dir=scratch) as temp:
        env = isolated_env(Path(temp), [root / 'agent'])
        code = ('from pathlib import Path; from hermes_cli._launchers import ensure_install_launchers; '
                f'r=Path({str(root / "agent")!r}); ensure_install_launchers(r,r/".hermes/bin")')
        contained_command([str(python), '-B', '-s', '-c', code], Path(temp),
                          [root / 'agent', root / 'runtime'],
                          writes=[root / 'agent/.hermes/bin'], exec_roots=[root / 'runtime'], env=env)
    for payload in ('agent', 'webui', 'runtime'):
        canary.inventory(root / payload)  # reject external links before chmod
        release_build.seal(root / payload)
    for item in manifest['services'].values():
        item['inventory'] = launcher.inventory(item['repo'])
        item.pop('runtimes', None)
    manifest['services']['agent']['runtimes'] = [
        {'root': str(root / 'runtime'), 'inventory': launcher.inventory(root / 'runtime')}]
    (root / 'release.json').write_bytes(encoded(manifest))
    release_build.seal(root)
    if canary.inventory(old) != baseline_inventory:
        raise RuntimeError('Baseline payload changed during build')
    if baseline_path.read_bytes() != baseline_bytes:
        raise RuntimeError('Selected release changed during build; refuse certification')
    return verify(cfg)


def prepare(cfg):
    """One-command local gates. Never select, signal, or modify control-plane state."""
    validate_config_paths(cfg)
    baseline_path = Path(cfg['baseline'])
    selected_bytes = baseline_path.read_bytes()
    baseline = launcher.load_manifest(baseline_path)
    old_root = Path(baseline['services']['agent']['repo']).parent
    check_placement(cfg, baseline)
    if Path(sys.executable).resolve().is_relative_to(old_root):
        raise RuntimeError('Use a nonproduction preparation interpreter')
    Path(cfg['scratch']).mkdir(parents=True, exist_ok=True)
    root = Path(cfg['output'])
    evidence = Path(cfg['evidence_dir'])
    if not evidence.is_absolute() or evidence.is_symlink():
        raise RuntimeError('evidence_dir must be absolute and non-symlink')
    evidence.mkdir(parents=True, exist_ok=True)
    run_dir = evidence / str(time.time_ns())
    run_dir.mkdir()
    report = {'status': 'NOT_READY', 'production_selected': False,
              'production_restarted': False, 'gates': {}, 'report': str(run_dir / 'report.json')}
    try:
        scripts = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory(prefix='release-tests-', dir=cfg['scratch']) as temp:
            env = isolated_env(Path(temp), [scripts])
            env['HERMES_CANARY_SCRATCH'] = cfg['scratch']
            result = subprocess.run([sys.executable, '-B', '-m', 'unittest', 'discover',
                                     '-s', str(scripts), '-p', 'test_*.py', '-v'],
                                    cwd=temp, env=env, capture_output=True, text=True, timeout=180)
            (run_dir / 'workflow-tests.log').write_text(result.stdout + result.stderr)
            if result.returncode:
                raise RuntimeError('Workflow tests failed; inspect evidence log')
        report['gates']['static'] = verify(cfg) if root.exists() else build(cfg)
        canary = subprocess.run([sys.executable, '-B', str(scripts / 'candidate_canary.py'),
                                 '--python', str(root / 'runtime/venv/bin/python'),
                                 '--runtime', str(root / 'runtime'),
                                 '--agent', str(root / 'agent'), '--agent-sha', cfg['agent_commit'],
                                 '--webui', str(root / 'webui'), '--webui-sha', cfg['webui_commit']],
                                env={**isolated_env(run_dir), 'HERMES_CANARY_SCRATCH': cfg['scratch']},
                                capture_output=True, text=True, timeout=300)
        (run_dir / 'canary-command.log').write_text(canary.stdout + canary.stderr)
        if canary.returncode:
            raise RuntimeError('Actual isolated runtime canary failed')
        canary_report = Path(canary.stdout.strip().splitlines()[-1])
        data = json.loads(canary_report.read_text())
        if data['status'] != 'passed' or not data.get('inventory_unchanged') or data['cleanup']['errors']:
            raise RuntimeError('Canary did not certify startup and cleanup')
        report['gates']['canary'] = data
        report['gates']['post_canary'] = verify(cfg)
        if baseline_path.read_bytes() != selected_bytes:
            raise RuntimeError('Selected release changed during preparation')
        # Preserve evidence beyond scratch's retention window.
        shutil.copytree(canary_report.parent, run_dir / 'canary')
        from select_for_user_restart import audit_routes
        old = launcher.load_manifest(Path(cfg['baseline']))
        new = launcher.load_manifest(root / 'release.json')
        report['gates']['restart_boundary'] = audit_routes(old, new, Path(cfg['controls']))
        # Offline source evidence is negative only; it cannot authorize selection.
        report['status'] = 'APP_SMOKE_PASSED_DEPLOYMENT_BLOCKED'
        return report
    except Exception as exc:
        report['error'] = str(exc)
        raise
    finally:
        (run_dir / 'report.json').write_bytes(encoded(report))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('action', choices=('build', 'verify', 'prepare'))
    args = parser.parse_args()
    try:
        cfg = config_read(args.config)
        report = {'build': build, 'verify': verify, 'prepare': prepare}[args.action](cfg)
        summary = {k: v for k, v in report.items() if k != 'gates'}
        print(json.dumps(summary, indent=2))
        if args.action == 'prepare':
            return 2  # Selection remains intentionally inadmissible on this controller.
    except Exception as exc:
        print(json.dumps({'status': 'NOT_READY', 'error': str(exc)}), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
