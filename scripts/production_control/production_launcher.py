#!/usr/bin/env python3
"""Launch an approved frozen runtime, never a mutable development checkout.

Release preparation does the Git/provenance work. Startup is offline and verifies
local bytes, dependencies and executables, not branch names or remote availability.
This script is deliberately standard-library-only and lives outside either service.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

BASE = Path(__file__).resolve().parent
MANIFEST = BASE / 'production-release.json'


def inventory(root):
    """Hash all files; omit only Git metadata.

    Bytecode is part of the receipt too: PYTHONDONTWRITEBYTECODE prevents new
    caches but does not prevent reading a poisoned existing cache.
    Unexpected files are also rejected: a json.py dropped beside the entry point
must not shadow an import. No blanket Git ignore or untracked-file exemption.
"""
    root = Path(root).resolve(strict=True)
    result = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d != '.git')
        for name in sorted(dirs + files):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                target = path.resolve(strict=True)
                if not target.is_relative_to(root):
                    raise RuntimeError(f'External symlink in release: {relative}')
                result[relative] = {'link': os.readlink(path)}
            elif path.is_file():
                digest = hashlib.sha256()
                with path.open('rb') as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b''):
                        digest.update(block)
                result[relative] = {'sha256': digest.hexdigest(),
                                    'executable': bool(path.stat().st_mode & 0o111)}
    return result


def load_manifest(path=None):
    path = Path(path or MANIFEST)
    data = json.loads(path.read_text())
    if not isinstance(data, dict) or data.get('schema_version') != 2:
        raise RuntimeError('Unsupported release manifest; prepare a frozen schema-2 release')
    if not isinstance(data.get('services'), dict) or not data['services']:
        raise RuntimeError('Release has no services')
    return data


def validate(service, services, seen=None):
    seen = set() if seen is None else seen
    if service in seen:
        raise RuntimeError('Circular production service dependency')
    seen.add(service)
    item = services[service]
    repo = Path(item['repo'])
    if not repo.is_absolute() or repo.is_symlink() or not repo.is_dir():
        raise RuntimeError(f'{service}: release must be an existing absolute, non-symlink directory')
    expected = item.get('inventory')
    if not isinstance(expected, dict) or not expected or inventory(repo) != expected:
        raise RuntimeError(f'{service}: approved runtime content mismatch; preserve running service and rebuild release')
    for runtime in item.get('runtimes', []):
        if inventory(runtime['root']) != runtime['inventory']:
            raise RuntimeError(f'{service}: approved interpreter/dependency content mismatch')
    argv = item.get('argv')
    if not isinstance(argv, list) or not argv or not all(isinstance(v, str) and v for v in argv):
        raise RuntimeError(f'{service}: invalid command')
    if not Path(argv[0]).is_absolute() or not os.access(argv[0], os.X_OK):
        raise RuntimeError(f'{service}: missing executable')
    cwd = Path(item['cwd'])
    if not cwd.is_absolute() or not cwd.is_dir():
        raise RuntimeError(f'{service}: missing working directory')
    for file in item.get('env_files', []):
        path = Path(file)
        if not path.is_absolute() or not path.is_file() or not os.access(path, os.R_OK):
            raise RuntimeError(f'{service}: missing environment file')
        if path.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise RuntimeError(f'{service}: environment file is writable by others')
    for dependency in item.get('requires', []):
        validate(dependency, services, seen.copy())
    return item


def launch_environment(item):
    env = os.environ.copy()
    for name in ('PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP', '_HERMES_GATEWAY'):
        env.pop(name, None)
    env.update(item.get('env', {}))
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    env['PYTHONNOUSERSITE'] = '1'
    return env


# Read credential files only in the approved interpreter, then restore the release's
# authoritative paths. No shell sourcing, bootstrap installer, or network update.
_ENTRY = '''import json,os,sys
item=json.loads(sys.argv[1])
if item.get("env_files"):
 from dotenv import dotenv_values
 for path in item["env_files"]:
  os.environ.update({k:v for k,v in dotenv_values(path,interpolate=False).items() if v is not None})
for name in ("PYTHONPATH","PYTHONHOME","PYTHONSTARTUP","_HERMES_GATEWAY"):
 os.environ.pop(name,None)
os.environ.update(item.get("env",{}))
os.environ["PYTHONDONTWRITEBYTECODE"]="1"
os.environ["PYTHONNOUSERSITE"]="1"
os.chdir(item["cwd"])
os.execve(item["argv"][0],item["argv"],os.environ)
'''


def launch_command(item):
    if not item.get('env_files'):
        return item['argv']
    runtime = {key: item[key] for key in ('argv', 'cwd', 'env', 'env_files') if key in item}
    return [item['argv'][0], '-c', _ENTRY, json.dumps(runtime)]


def probe(item):
    """Import the actual selected modules with disposable state and no credentials."""
    modules = item.get('probe_modules', [])
    if not modules:
        return
    with tempfile.TemporaryDirectory(prefix='hermes-preflight-') as temporary:
        env = {k: v for k, v in launch_environment(item).items()
               if k in {'PATH', 'PYTHONPATH', 'PYTHONNOUSERSITE', 'PYTHONDONTWRITEBYTECODE',
                        'HERMES_WEBUI_AGENT_DIR', 'HERMES_WEBUI_AUTO_INSTALL'}}
        env.update(HOME=temporary, HERMES_HOME=temporary, HERMES_BASE_HOME=temporary,
                   HERMES_WEBUI_STATE_DIR=temporary, HERMES_CONFIG_PATH=str(Path(temporary) / 'config.yaml'))
        code = ('import importlib,json,os,pathlib,sys; '
                'mods=json.loads(sys.argv[1]); expected=pathlib.Path(sys.argv[2]).resolve(); '
                'loaded=[importlib.import_module(m) for m in mods]; '
                'bad=[m.__name__ for m in loaded if not pathlib.Path(m.__file__).resolve().is_relative_to(expected)]; '
                'sys.exit(2 if bad else 0)')
        result = subprocess.run([item['argv'][0], '-c', code, json.dumps(modules), item['repo']],
                                cwd=item['repo'], env=env, capture_output=True, timeout=30)
        if result.returncode:
            # Imports can print config/auth material: never return their raw stderr.
            raise RuntimeError('Runtime import preflight failed; inspect isolated dependency installation')


def preflight(manifest):
    for service in manifest['services']:
        item = validate(service, manifest['services'])
        probe(item)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('service', choices=('agent', 'webui'))
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--manifest', type=Path, default=MANIFEST)
    args = parser.parse_args()
    manifest = load_manifest(args.manifest)
    item = validate(args.service, manifest['services'])
    probe(item)
    print(f'production runtime OK: {args.service} {item["commit"]}', flush=True)
    if args.check:
        return
    os.chdir(item['cwd'])
    argv = launch_command(item)
    os.execve(argv[0], argv, launch_environment(item))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(f'PRODUCTION START REFUSED: {exc}', file=sys.stderr, flush=True)
        raise SystemExit(78)
