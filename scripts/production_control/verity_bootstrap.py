#!/usr/bin/env python3
"""Stage an independently starting Verity bootstrap runtime; never activates it.

The signed Verity.app settings path is intentionally not changed here. Activation,
compatibility-pointer updates and donor-release retention are separate decisions.
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

import production_launcher as launcher
import release_build

DESCRIPTOR = 'bootstrap.json'
REQUIRED_ROOT_ENTRIES = {'python', 'venv', DESCRIPTOR}
SCHEMA_VERSION = 1


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def atomic_write(path, raw, mode=0o444):
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def source_runtime(manifest_path):
    raw = manifest_path.read_bytes()
    manifest = json.loads(raw)
    root = manifest_path.parent.resolve(strict=True)
    require(manifest_path.resolve() == manifest_path and manifest_path.name == 'release.json',
            'Baseline manifest must be a canonical release.json')
    require(manifest.get('release_id') == root.name, 'Baseline release identity mismatch')
    runtimes = manifest.get('services', {}).get('agent', {}).get('runtimes')
    require(isinstance(runtimes, list) and len(runtimes) == 1,
            'Baseline must declare exactly one bootstrap runtime')
    runtime = Path(runtimes[0]['root'])
    require(runtime == root / 'runtime' and runtime.resolve() == runtime,
            'Baseline runtime escapes its release')
    require(launcher.inventory(runtime) == runtimes[0]['inventory'],
            'Baseline bootstrap runtime differs from its approved inventory')
    python = runtime / 'venv/bin/python'
    require(python.is_file() and os.access(python, os.X_OK),
            'Baseline bootstrap Python is unavailable')
    return manifest, root, runtime, python, digest(raw)


def payload(root):
    inventory = launcher.inventory(root)
    inventory.pop(DESCRIPTOR, None)
    return {
        'root': str(root),
        'python': str(root / 'venv/bin/python'),
        'inventory': inventory,
    }


def verify(root):
    root = Path(root)
    require(root.is_absolute() and root.resolve() == root
            and root.is_dir() and not root.is_symlink(),
            'Bootstrap root must be a canonical directory')
    require({path.name for path in root.iterdir()} == REQUIRED_ROOT_ENTRIES,
            'Unexpected bootstrap root content')
    descriptor_path = root / DESCRIPTOR
    descriptor = json.loads(descriptor_path.read_text())
    require(type(descriptor) is dict and set(descriptor) == {
        'schema_version', 'kind', 'status', 'source', 'payload'}
        and descriptor['schema_version'] == SCHEMA_VERSION
        and descriptor['kind'] == 'verity-bootstrap-runtime'
        and descriptor['status'] == 'staged_not_active'
        and stat.S_IMODE(descriptor_path.stat().st_mode) == 0o444,
        'Invalid bootstrap descriptor')
    expected = descriptor['payload']
    require(set(expected) == {'root', 'python', 'inventory'}
            and expected['root'] == str(root)
            and expected['python'] == str(root / 'venv/bin/python'),
            'Bootstrap payload path mismatch')
    require(type(expected['inventory']) is dict
            and DESCRIPTOR not in expected['inventory'],
            'Bootstrap inventory mismatch')
    current = payload(root)
    require(current == expected, 'Bootstrap payload differs from its approved inventory')
    python = Path(expected['python'])
    require(python.is_file() and os.access(python, os.X_OK),
            'Bootstrap Python is unavailable')
    code = ('import json,sys,sysconfig; print(json.dumps({'
            '"base":sys.base_prefix,"prefix":sys.prefix,'
            '"site":sysconfig.get_paths()["purelib"]}))')
    env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(root),
           'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1'}
    result = subprocess.run([str(python), '-I', '-B', '-c', code],
                            env=env, capture_output=True, text=True, timeout=60)
    require(result.returncode == 0, 'Bootstrap interpreter did not start')
    paths = json.loads(result.stdout)
    require(set(paths) == {'base', 'prefix', 'site'}
            and all(Path(value).resolve().is_relative_to(root) for value in paths.values()),
            'Bootstrap interpreter escaped into an external runtime')
    require(payload(root) == expected, 'Bootstrap changed during verification')
    return descriptor


def stage(manifest_path, output):
    manifest_path = Path(manifest_path).absolute()
    output = Path(output).absolute()
    manifest, source_root, runtime, python, manifest_sha = source_runtime(manifest_path)
    require(not output.exists() and not output.is_symlink(),
            'Bootstrap output already exists; stage to a fresh path')
    require(output.parent.is_dir() and output.parent.resolve() == output.parent,
            'Bootstrap output parent must be canonical and existing')
    require(not source_root.is_relative_to(output) and not output.is_relative_to(source_root),
            'Bootstrap donor and output must be disjoint')
    output.mkdir(mode=0o700)
    try:
        release_build.private_python(python, output, source_root=runtime)
        release_build.seal(output / 'python')
        release_build.seal(output / 'venv')
        descriptor = {
            'schema_version': SCHEMA_VERSION,
            'kind': 'verity-bootstrap-runtime',
            'status': 'staged_not_active',
            'source': {
                'release_id': manifest['release_id'],
                'manifest': str(manifest_path),
                'manifest_sha256': manifest_sha,
            },
            'payload': payload(output),
        }
        atomic_write(output / DESCRIPTOR, encoded(descriptor))
        output.chmod(0o555)
        # Verification invokes the interpreter twice. Isolated mode, disabled
        # bytecode and exact inventory checks prove no payload drift.
        verify(output)
        return verify(output)
    except BaseException:
        # A failed staging directory is evidence, not an activation candidate.
        # Do not silently rebuild into it or relabel it as verified.
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest='command', required=True)
    stage_parser = subparsers.add_parser('stage')
    stage_parser.add_argument('--baseline', type=Path, required=True,
                              help='Existing baseline release.json')
    stage_parser.add_argument('--output', type=Path, required=True)
    verify_parser = subparsers.add_parser('verify')
    verify_parser.add_argument('root', type=Path)
    args = parser.parse_args(argv)
    if args.command == 'stage':
        descriptor = stage(args.baseline, args.output)
        result = {'status': 'staged_not_active', 'root': descriptor['payload']['root'],
                  'python': descriptor['payload']['python'],
                  'source': descriptor['source']}
    else:
        descriptor = verify(args.root)
        result = {'status': 'verified_staged_not_active',
                  'root': descriptor['payload']['root'],
                  'python': descriptor['payload']['python']}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status': 'verification_failed', 'error': str(error)}),
              file=sys.stderr)
        raise SystemExit(1)
