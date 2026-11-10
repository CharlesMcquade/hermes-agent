#!/usr/bin/env python3
"""Activate a staged Verity bootstrap with exact-input guards and rollback.

Planning writes only a fresh audit directory. Apply changes only the explicitly
reviewed compatibility projection, watchdog interpreter and service-manager
interpreter. It never selects an application release or restarts a service.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys

import production_launcher as launcher
import restart_production as controller
import verity_bootstrap as bootstrap

SCHEMA_VERSION = 1
PLAN_NAME = 'activation.json'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def atomic_bytes(path, raw, mode):
    bootstrap.atomic_write(Path(path), raw, mode)


def atomic_link(path, target):
    path = Path(path)
    temporary = path.with_name('.' + path.name + '.bootstrap-new')
    require(not os.path.lexists(temporary), 'Stale bootstrap temporary link exists')
    try:
        temporary.symlink_to(target)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.lexists(temporary):
            temporary.unlink()


def new_watchdog(raw, new_python, watchdog_path):
    lines = raw.decode().splitlines(keepends=True)
    require(len(lines) == 2 and lines[0] == '#!/bin/sh\n' and lines[1].startswith('exec '),
            'Unrecognized watchdog wrapper')
    words = shlex.split(lines[1])
    require(len(words) == 7 and words[0] == 'exec' and words[2] == '-B'
            and Path(words[3]) == Path(watchdog_path)
            and words[4] == '>>' and words[6] == '2>&1'
            and Path(words[5]).is_absolute(),
            'Unrecognized watchdog interpreter route')
    words[1] = str(new_python)
    # exec and redirection operators are shell syntax, never quoted arguments.
    fields = [words[0], shlex.quote(words[1]), words[2], shlex.quote(words[3]),
              words[4], shlex.quote(words[5]), words[6]]
    return ('#!/bin/sh\n' + ' '.join(fields) + '\n').encode()


def new_service_manager(raw, new_python, launcher_path):
    data = json.loads(raw)
    require(set(data) == {'webui_restart_preflight'}, 'Unexpected service-manager keys')
    preflight = data['webui_restart_preflight']
    require(type(preflight) is list and len(preflight) == 4
            and preflight[1:] == [str(launcher_path), 'webui', '--check'],
            'Unrecognized service-manager preflight route')
    preflight[0] = str(new_python)
    return bootstrap.encoded(data)


def plan(bootstrap_root, compatibility, dependency_receipt, watchdog_script,
         service_manager, output, selected_manifest):
    descriptor = bootstrap.verify(bootstrap_root)
    python = Path(descriptor['payload']['python'])
    new_python = str(python)
    compatibility = Path(compatibility)
    dependency_receipt = Path(dependency_receipt)
    watchdog_script = Path(watchdog_script)
    service_manager = Path(service_manager)
    output = Path(output)
    selected_manifest = Path(selected_manifest)
    base = selected_manifest.resolve().parent
    require(compatibility.is_symlink(), 'Signed compatibility path is not a symlink')
    require(Path(os.readlink(compatibility)) != python,
            'Compatibility projection already targets the staged interpreter')
    dependency_raw = dependency_receipt.read_bytes()
    dependency = json.loads(dependency_raw)
    require(set(dependency) == {
        'role', 'path', 'target', 'source_inventory_verified',
        'preserve_until_signed_launcher_migration'}
        and dependency['path'] == str(compatibility)
        and dependency['target'] == os.readlink(compatibility),
        'Compatibility dependency record does not match the live link')
    dependency['target'] = new_python
    watchdog_raw = watchdog_script.read_bytes()
    manager_raw = service_manager.read_bytes()
    launcher_path = base / 'production_launcher.py'
    new_watchdog_raw = new_watchdog(watchdog_raw, python, base / 'watchdog.py')
    new_manager_raw = new_service_manager(manager_raw, python, launcher_path)
    selected_raw = selected_manifest.read_bytes()
    native = json.loads(selected_raw)
    native_identity(base, native)
    prior = {
        'compatibility': {'path': str(compatibility), 'target': os.readlink(compatibility)},
        'dependency_receipt': {
            'path': str(dependency_receipt), 'data': dependency_raw.decode(),
            'mode': stat.S_IMODE(dependency_receipt.stat().st_mode),
        },
        'watchdog': {
            'path': str(watchdog_script), 'data': watchdog_raw.decode(),
            'mode': stat.S_IMODE(watchdog_script.stat().st_mode),
        },
        'service_manager': {
            'path': str(service_manager), 'data': manager_raw.decode(),
            'mode': stat.S_IMODE(service_manager.stat().st_mode),
        },
    }
    value = {
        'schema_version': SCHEMA_VERSION,
        'kind': 'verity-bootstrap-activation',
        'status': 'planned_not_active',
        'selected_manifest': str(selected_manifest),
        'selected_manifest_sha256': bootstrap.digest(selected_raw),
        'base': str(base),
        'python': new_python,
        'prior': prior,
        'next': {
            'compatibility_target': new_python,
            'dependency_data': bootstrap.encoded(dependency).decode(),
            'watchdog_data': new_watchdog_raw.decode(),
            'service_manager_data': new_manager_raw.decode(),
        },
    }
    require(not output.exists() and not output.is_symlink(), 'Audit directory already exists')
    output.mkdir(mode=0o700)
    bootstrap.atomic_write(output / PLAN_NAME, bootstrap.encoded(value))
    return value


def paths_for(name, plan_value):
    return Path(plan_value['prior'][name]['path'])


def verify(plan_value, run_checks=True):
    verify_runtime(plan_value)
    link = paths_for('compatibility', plan_value)
    require(link.is_symlink() and os.readlink(link) == plan_value['python'],
            'Compatibility projection readback failed')
    for name in ('dependency_receipt', 'watchdog', 'service_manager'):
        path = paths_for(name, plan_value)
        key = {'dependency_receipt': 'dependency_data',
               'watchdog': 'watchdog_data',
               'service_manager': 'service_manager_data'}[name]
        require(path.read_bytes() == plan_value['next'][key].encode(),
                'Activation readback differs: ' + name)
        require(stat.S_IMODE(path.stat().st_mode) == plan_value['prior'][name]['mode'],
                'Activation mode differs: ' + name)
    base = Path(plan_value['base'])
    if run_checks:
        shell = subprocess.run(['/bin/sh', '-n', str(paths_for('watchdog', plan_value))],
                               capture_output=True, timeout=30)
        require(shell.returncode == 0, 'Watchdog shell syntax check failed')
        checks = []
        for role in ('webui', 'agent'):
            command = [plan_value['python'], '-I', '-B',
                       str(base / 'production_launcher.py'), role, '--check',
                       '--manifest', plan_value['selected_manifest']]
            env = {'HOME': str(base.parent), 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin',
                   'HERMES_HOME': str(base.parent), 'PYTHONDONTWRITEBYTECODE': '1',
                   'PYTHONNOUSERSITE': '1'}
            for _ in range(2):
                result = subprocess.run(command, capture_output=True, text=True,
                                        env=env, timeout=180)
                require(result.returncode == 0, 'Bootstrap preflight failed: ' + role)
                require('production runtime OK: ' + role in result.stdout,
                        'Bootstrap preflight proof missing: ' + role)
                checks.append(role)
        return checks
    return []


def verify_runtime(plan_value):
    descriptor = bootstrap.verify(Path(plan_value['python']).parents[2])
    require(descriptor['payload']['python'] == plan_value['python'],
            'Activated interpreter differs from reviewed payload')
    selected_raw = Path(plan_value['selected_manifest']).read_bytes()
    require(bootstrap.digest(selected_raw) == plan_value['selected_manifest_sha256'],
            'Selected application manifest changed since activation planning')
    native_identity(Path(plan_value['base']), json.loads(selected_raw))


def apply(plan_path, approval, expected_sha256):
    require(approval is True, 'Explicit --approve required')
    plan_path = Path(plan_path)
    plan_raw = plan_path.read_bytes()
    require(bootstrap.digest(plan_raw) == expected_sha256,
            'Bootstrap activation plan pin mismatch')
    value = json.loads(plan_raw)
    require(set(value) == {
        'schema_version', 'kind', 'status', 'selected_manifest',
        'selected_manifest_sha256', 'base', 'python',
        'prior', 'next'} and value['schema_version'] == SCHEMA_VERSION
        and value['kind'] == 'verity-bootstrap-activation'
        and value['status'] == 'planned_not_active', 'Invalid bootstrap activation plan')
    base = Path(value['base'])
    verify_runtime(value)
    original_link = value['prior']['compatibility']['target']
    compatibility = paths_for('compatibility', value)
    require(compatibility.is_symlink()
            and os.readlink(compatibility) == original_link,
            'Compatibility projection changed since planning')
    for name in ('dependency_receipt', 'watchdog', 'service_manager'):
        prior = value['prior'][name]
        path = paths_for(name, value)
        require(path.read_bytes() == prior['data'].encode(),
                'Activation input changed since planning: ' + name)
        require(stat.S_IMODE(path.stat().st_mode) == prior['mode'],
                'Activation input mode changed: ' + name)
    restored = []
    try:
        with controller.control_lock(base):
            # Re-check every current input after acquiring the management lock.
            require(compatibility.is_symlink()
                    and os.readlink(compatibility) == original_link,
                    'Compatibility projection raced activation')
            for name in ('dependency_receipt', 'watchdog', 'service_manager'):
                require(paths_for(name, value).read_bytes()
                        == value['prior'][name]['data'].encode(),
                        'Activation input raced planning: ' + name)
            restored.append('compatibility')
            atomic_link(compatibility, value['python'])
            require(os.readlink(compatibility) == value['python'],
                    'Could not activate the reviewed bootstrap link')
            receipt = paths_for('dependency_receipt', value)
            restored.append('dependency_receipt')
            atomic_bytes(receipt, value['next']['dependency_data'].encode(),
                         value['prior']['dependency_receipt']['mode'])
            watchdog = paths_for('watchdog', value)
            restored.append('watchdog')
            atomic_bytes(watchdog, value['next']['watchdog_data'].encode(),
                         value['prior']['watchdog']['mode'])
            manager = paths_for('service_manager', value)
            restored.append('service_manager')
            atomic_bytes(manager, value['next']['service_manager_data'].encode(),
                         value['prior']['service_manager']['mode'])
            checks = verify(value)
        result_path = plan_path.parent / 'result.json'
        result = dict(status='activated', python=value['python'],
                      preflight_checks=checks, rollback_available=str(plan_path.parent))
        bootstrap.atomic_write(result_path, bootstrap.encoded(result))
        return result
    except BaseException:
        errors = []
        with controller.control_lock(base):
            for name in reversed(restored):
                try:
                    prior = value['prior'][name]
                    if name == 'compatibility':
                        atomic_link(paths_for(name, value), original_link)
                    else:
                        atomic_bytes(paths_for(name, value), prior['data'].encode(), prior['mode'])
                except Exception as error:
                    errors.append(name + ': ' + str(error))
            for name in reversed(restored):
                try:
                    prior = value['prior'][name]
                    if name == 'compatibility':
                        require(os.readlink(compatibility) == original_link,
                                'Rollback link readback failed')
                    else:
                        path = paths_for(name, value)
                        require(path.read_bytes() == prior['data'].encode()
                                and stat.S_IMODE(path.stat().st_mode) == prior['mode'],
                                'Rollback readback failed: ' + name)
                except Exception as error:
                    errors.append(name + ': ' + str(error))
        if errors:
            raise RuntimeError('Activation failed; rollback incomplete: ' + '; '.join(errors))
        raise


def native_identity(base, manifest):
    from native_identity import validate_bundle
    validate_bundle(manifest, base, controller.Host())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    make = commands.add_parser('plan')
    make.add_argument('--bootstrap', required=True, type=Path)
    make.add_argument('--compatibility', required=True, type=Path)
    make.add_argument('--dependency-receipt', required=True, type=Path)
    make.add_argument('--watchdog', required=True, type=Path)
    make.add_argument('--service-manager', required=True, type=Path)
    make.add_argument('--selected-manifest', required=True, type=Path)
    make.add_argument('--output', required=True, type=Path)
    act = commands.add_parser('apply')
    act.add_argument('--plan', required=True, type=Path)
    act.add_argument('--plan-sha256', required=True)
    act.add_argument('--approve', action='store_true')
    check = commands.add_parser('verify')
    check.add_argument('--plan', required=True, type=Path)
    check.add_argument('--no-checks', action='store_true')
    args = parser.parse_args(argv)
    if args.command == 'plan':
        value = plan(args.bootstrap, args.compatibility, args.dependency_receipt,
                     args.watchdog, args.service_manager, args.output, args.selected_manifest)
        result = dict(status='planned_not_active', plan=str(args.output / PLAN_NAME))
    elif args.command == 'verify':
        value = json.loads(args.plan.read_bytes())
        checks = verify(value, run_checks=not args.no_checks)
        result = dict(status='verified_active', preflight_checks=checks)
    else:
        result = apply(args.plan, args.approve, args.plan_sha256)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status': 'activation_failed', 'error': str(error)}),
              file=sys.stderr)
        raise SystemExit(1)
