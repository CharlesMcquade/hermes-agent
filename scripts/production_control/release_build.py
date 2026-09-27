#!/usr/bin/env python3
"""Prepare an offline, versioned Agent/WebUI pair. Never stop or change a service.

Run after testing exact source commits. This copies a working Python distribution
and installed dependencies; it does not resolve or install packages from a network.
The output manifest is a candidate, not an activation or health receipt.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

import production_launcher as launcher


def run(argv, **kwargs):
    return subprocess.check_output(argv, text=True, stderr=subprocess.PIPE, timeout=180, **kwargs).strip()


def git(repo, *args):
    return run(['/usr/bin/git', '-C', str(repo), *args])


def snapshot(source, ref, destination):
    sha = git(source, 'rev-parse', '--verify', ref + '^{commit}')
    destination.mkdir()
    git(destination, 'init', '--quiet')
    git(destination, 'fetch', '--quiet', '--depth=1', '--no-tags', str(source), sha)
    git(destination, 'checkout', '--quiet', '--detach', 'FETCH_HEAD')
    if git(destination, 'rev-parse', 'HEAD') != sha:
        raise RuntimeError('Snapshot identity mismatch')
    return sha


def ignore_runtime(directory, names):
    return [name for name in names if name == '__pycache__' or name.endswith('.pyc') or
            name.startswith('__editable__')]


def private_python(source_python, root):
    info = json.loads(run([str(source_python), '-c',
        'import json,sys,sysconfig; print(json.dumps({"base":sys.base_prefix,"site":sysconfig.get_paths()["purelib"]}))']))
    base = root / 'python'
    shutil.copytree(Path(info['base']).resolve(), base, symlinks=True, ignore=ignore_runtime)
    python = base / 'bin' / 'python3'
    venv = root / 'venv'
    run([str(python), '-m', 'venv', '--without-pip', str(venv)], env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    executable = venv / 'bin' / 'python'
    site = Path(run([str(executable), '-c', 'import sysconfig; print(sysconfig.get_paths()["purelib"])']))
    shutil.copytree(info['site'], site, dirs_exist_ok=True, symlinks=True, ignore=ignore_runtime)
    # Replace all console-script launchers with the preserved package entry points
    # so child tools cannot fall through to a development interpreter on PATH.
    command = '''import importlib.metadata,json
print(json.dumps({e.name:e.value for e in importlib.metadata.entry_points(group="console_scripts")}))'''
    entries = json.loads(run([str(executable), '-c', command]))
    for name, value in entries.items():
        if '/' in name or ':' not in value:
            continue
        module, symbol = value.split(':', 1)
        symbol = symbol.split(' [', 1)[0]
        script = venv / 'bin' / name
        script.write_text(f'#!{executable}\nimport importlib,sys\nobj=importlib.import_module({module!r})\n'
                          f'for part in {symbol!r}.split("."): obj=getattr(obj,part)\n'
                          'if __name__ == "__main__": sys.exit(obj())\n')
        script.chmod(0o755)
    return executable


def seal(root):
    """Discourage in-place edits; deployment produces another directory instead."""
    for directory, dirs, files in os.walk(root):
        for name in files:
            path = Path(directory) / name
            if not path.is_symlink():
                path.chmod(path.stat().st_mode & ~0o222)
        Path(directory).chmod(Path(directory).stat().st_mode & ~0o222)


def build(args):
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    source_paths = {'agent': args.agent_repo.resolve(), 'webui': args.webui_repo.resolve()}
    refs = {'agent': args.agent_ref, 'webui': args.webui_ref}
    commits = {name: snapshot(source, refs[name], root / name) for name, source in source_paths.items()}
    runtime = root / 'runtime'
    # Do not resolve a venv's executable symlink: that loses its site-packages.
    python = private_python(args.python.absolute(), runtime)
    state = args.state_dir.resolve()
    agent = root / 'agent'
    webui = root / 'webui'
    env = {'HERMES_HOME': str(state), 'HERMES_BASE_HOME': str(state),
           'PYTHONPATH': str(agent), 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1',
           'VIRTUAL_ENV': str(python.parent.parent),
           'PATH': str(python.parent) + ':' + os.environ.get('PATH', '/usr/bin:/bin'),
           'HERMES_WEBUI_AGENT_DIR': str(agent), 'HERMES_WEBUI_AUTO_INSTALL': '0',
           'HERMES_WEBUI_FOREGROUND': '1', 'HERMES_WEBUI_STATE_DIR': str(state / 'webui')}
    services = {
        'agent': {'repo': str(agent), 'cwd': str(state),
                  'argv': [str(python), '-m', 'hermes_cli.stderr_timestamp', '--error-log',
                           str(state / 'logs/gateway.error.log'), '--', str(python), '-m',
                           'hermes_cli.main', 'gateway', 'run', '--external-supervisor'],
                  'requires': [], 'probe_modules': ['hermes_cli.main', 'run_agent']},
        'webui': {'repo': str(webui), 'cwd': str(webui),
                  'argv': [str(python), str(webui / 'server.py')], 'requires': ['agent'],
                  'probe_modules': ['api.config', 'server'], 'env_files': [str(args.webui_env.resolve())]},
    }
    # The local manager, not generic install/update, owns release activation.
    for name, item in services.items():
        service_env = dict(env, PYTHONSAFEPATH='1')
        if name == 'webui':
            service_env['PYTHONPATH'] = str(webui) + os.pathsep + str(agent)
        item.update(env=service_env, commit=commits[name],
                    version=git(root / name, 'describe', '--tags', '--always'),
                    plist_path=str(Path.home() / 'Library/LaunchAgents' /
                                   ('ai.hermes.gateway.plist' if name == 'agent' else 'com.charles.hermes-webui.plist')))
    seal(agent)
    seal(webui)
    seal(runtime)
    runtime_descriptor = {'root': str(runtime), 'inventory': launcher.inventory(runtime)}
    for item in services.values():
        item['inventory'] = launcher.inventory(item['repo'])
    services['agent']['runtimes'] = [runtime_descriptor]
    manifest = {'schema_version': 2, 'release_id': root.name, 'prepared_at': time.time(),
                'state_dir': str(state), 'health_url': args.health_url,
                'labels': {'agent': 'ai.hermes.gateway', 'webui': 'com.charles.hermes-webui'},
                'source_commits': commits, 'services': services,
                'verification_note': str(args.verification_note.resolve())}
    launcher.preflight(manifest)
    target = root / 'release.json'
    target.write_text(json.dumps(manifest, indent=2) + '\n')
    target.chmod(0o444)
    print(json.dumps({'status': 'prepared_not_activated', 'manifest': str(target), 'commits': commits}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('agent-repo', 'webui-repo', 'python', 'output', 'state-dir', 'webui-env', 'verification-note'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--agent-ref', default='HEAD')
    parser.add_argument('--webui-ref', default='HEAD')
    parser.add_argument('--health-url', default='http://127.0.0.1:8787/health')
    args = parser.parse_args()
    if not args.verification_note.is_file():
        parser.error('An existing verification note is required; preparation is not test certification')
    build(args)


if __name__ == '__main__':
    main()
