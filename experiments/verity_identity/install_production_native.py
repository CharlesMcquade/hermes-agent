"""Opt-in first installation only. Never select, start, sign, or delete artifacts."""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import stat

import stage_production_native as stage
from restart_production import Controller, atomic_write, control_lock, require, save_json

RECEIPT = 'native-install-receipt.json'
PHASES = {'prepared', 'controls_installed', 'app_installed', 'installed',
          'restoring', 'restored_artifacts_retained'} | {
              'published_' + name for name in stage.wrappers(Path('/base'), Path('/version'))}


def safe(path, *, missing=False):
    """Reject lexical aliases, symlinks, special files and writable ancestors."""
    path = Path(path)
    require(path.is_absolute() and str(path) == os.path.normpath(str(path))
            and path == path.resolve(), 'Noncanonical path')
    for item in (path, *path.parents):
        if not item.exists():
            require(missing, 'Missing path: ' + str(item))
            continue
        info = item.lstat()
        require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode), 'Unsafe file type')
        require(info.st_uid in ({os.getuid()} if item == path else {0, os.getuid()}),
                'Unexpected path owner')
        require(not info.st_mode & 0o022, 'Writable-by-others path')
        require(not info.st_mode & 0o7000, 'Special permission bits')
    return path


def snapshot(path):
    path = safe(path)
    return dict(data=base64.b64encode(path.read_bytes()).decode(),
                mode=stat.S_IMODE(path.stat().st_mode), uid=path.stat().st_uid)


def decode(record):
    require(set(record) == {'data', 'mode', 'uid'} and type(record['mode']) is int
            and 0 <= record['mode'] <= 0o777 and not record['mode'] & 0o022
            and record['uid'] == os.getuid(), 'Malformed baseline record')
    return base64.b64decode(record['data'], validate=True)


def terminal_activation(base):
    safe(base / 'activation-transaction.json', missing=True)
    txn = Controller(base).read_transaction()
    require(txn is None or txn['phase'] in {'verified', 'rolled_back'},
            'Unresolved activation transaction')


def locations(base, home, report):
    app = home / 'Applications/Verity.app'
    version = Path(report['final_control_version'])
    require(re.fullmatch(r'[A-Za-z0-9_-]+', version.name) is not None
            and version.parent == base / 'control-versions'
            and report['final_base'] == str(base)
            and report['final_bundle'] == str(app), 'Wrong installation destinations')
    safe(app, missing=True)
    safe(version, missing=True)
    # Require existing anchors: no recursive creation outside the bounded targets.
    safe(app.parent)
    safe(version.parent)
    return app, version


def baseline_paths(base, old):
    require(type(old.get('schema_version')) is int and old['schema_version'] == 2
            and 'native_host' not in old and 'launchd_overrides' not in old,
            'Initial legacy schema-2 selection required')
    Controller(base).validate_manifest(old)
    paths = [base / 'production-release.json'] + [
        Path(old['services'][r]['plist_path']) for r in stage.ROLES]
    require(len(set(paths)) == 3, 'Aliased baseline paths')
    return paths


def unchanged(receipt):
    base = Path(receipt['base'])
    terminal_activation(base)
    for path, record in receipt['baseline'].items():
        require(snapshot(Path(path)) == record, 'Legacy selection/plist baseline drift')


def save_receipt(base, receipt, phase):
    receipt['phase'] = phase
    payload = stage.encoded(receipt)
    save_json(base / RECEIPT, dict(schema_version=1, receipt=receipt,
                                 sha256=stage.digest(payload)))


def copy_tree(source, destination, *, controls=False):
    """Exclusive destination; fsync each file. Partial copies are retained."""
    safe(destination, missing=True)
    destination.mkdir(mode=0o700)
    for item in sorted(source.iterdir()):
        safe(item)
        target = destination / item.name
        if item.is_dir():
            copy_tree(item, target, controls=controls)
        else:
            atomic_write(target, item.read_bytes())
            target.chmod(0o444 if controls else stat.S_IMODE(item.stat().st_mode))
            with target.open('rb') as stream:
                os.fsync(stream.fileno())
    destination.chmod(0o555 if controls else stat.S_IMODE(source.stat().st_mode))
    for directory in (destination, destination.parent):
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def install(root, base, home, *, approve=False, runner=stage.run):
    require(approve is True, 'Explicit --approve-install required')
    root, base, home = safe(root), safe(base), safe(home)
    safe(base / 'control.lock', missing=True)
    with control_lock(base):
        terminal_activation(base)
        safe(base / RECEIPT, missing=True)
        require(not (base / RECEIPT).exists(), 'Existing install receipt; restore/reconcile first')
        # Walk all staged inputs before signature verification, including directories.
        for item in root.rglob('*'):
            safe(item)
        stage.verify_stage(root, runner=runner)
        report = json.loads((root / 'stage-report.json').read_text())
        require(report['status'] == 'staged_not_activated', 'Incomplete stage')
        app, version = locations(base, home, report)
        require(not app.exists() and not version.exists(), 'First-install destinations must not exist')
        old_bytes = (root / 'selected-manifest.json').read_bytes()
        old = json.loads(old_bytes)
        paths = baseline_paths(base, old)
        expected = [old_bytes] + [(root / 'rollback' / (r + '.plist')).read_bytes()
                                  for r in stage.ROLES]
        baseline = {str(p): snapshot(p) for p in paths}
        require(all(decode(baseline[str(p)]) == data for p, data in zip(paths, expected)),
                'Staged baseline drift')
        originals = {name: snapshot(base / name) for name in stage.wrappers(base, version)}
        require(all(decode(record) == (root / 'rollback/maintenance' / name).read_bytes()
                    for name, record in originals.items()), 'Wrapper baseline drift')
        new = {name: (root / 'maintenance' / name).read_bytes() for name in originals}
        control_source = root / 'control-versions' / version.name
        require({p.name for p in control_source.iterdir()} == set(stage.FILES) | {'control-receipt.json'},
                'Unexpected control files')
        require(json.loads((control_source / 'control-receipt.json').read_text()) == report['control_sha256'],
                'Control receipt mismatch')
        receipt = dict(base=str(base), home=str(home), report=report, baseline=baseline,
                       wrappers=originals, replacements={n: base64.b64encode(b).decode() for n, b in new.items()})
        unchanged(receipt)
        save_receipt(base, receipt, 'prepared')  # Before the first artifact/wrapper write.
        copy_tree(control_source, version, controls=True)
        require({n: stage.digest((version / n).read_bytes()) for n in stage.FILES}
                == report['control_sha256'], 'Installed controls drift')
        save_receipt(base, receipt, 'controls_installed')
        copy_tree(root / 'Verity.app', app)
        candidate = json.loads((root / 'candidate-release.json').read_text())
        require(stage.inventory(app) == candidate['native_host']['inventory'], 'Installed app drift')
        runner(['/usr/bin/codesign', '--verify', '--strict', '-R',
                '=' + candidate['native_host']['requirement'], str(app)])
        save_receipt(base, receipt, 'app_installed')
        for name, data in new.items():
            unchanged(receipt)
            require(snapshot(base / name) == originals[name], 'Wrapper changed before publication')
            atomic_write(base / name, data)  # Existing actual mode is preserved.
            require(snapshot(base / name) == dict(originals[name], data=receipt['replacements'][name]),
                    'Wrapper publication mismatch')
            save_receipt(base, receipt, 'published_' + name)
        unchanged(receipt)
        save_receipt(base, receipt, 'installed')
        return {'status': 'installed', 'selected_release_unchanged': True, 'activated': False}


def no_live_native_dependency(base, old):
    """Read-only loaded-job + process identity check; no state files/app imports."""
    controller = Controller(base)
    definitions = controller.definitions(old)
    jobs = controller.loaded(old, definitions)
    records = {}
    for role in stage.ROLES:
        pid = jobs[role]['pid']
        record = controller.host.process_identity(pid)
        require(record['pid'] == pid and record['uid'] == os.getuid()
                and record['ppid'] == 1
                and record['argv'] == old['services'][role]['argv']
                and record['executable'] == str(Path(record['argv'][0]).resolve()),
                'Cannot rule out live native dependency')
        records[role] = record
    require(controller.loaded(old, definitions) == jobs, 'Loaded jobs changed')
    require(all(controller.host.process_identity(jobs[r]['pid']) == records[r]
                for r in stage.ROLES), 'Live process identity changed')
    return True


def restore(base, home, *, approve=False, dependency_check=no_live_native_dependency):
    require(approve is True, 'Explicit --approve-restore required')
    base, home = safe(base), safe(home)
    safe(base / 'control.lock', missing=True)
    with control_lock(base):
        envelope = json.loads(safe(base / RECEIPT).read_text())
        require(envelope['schema_version'] == 1, 'Unknown receipt schema')
        receipt = envelope['receipt']
        require(stage.digest(stage.encoded(receipt)) == envelope['sha256'], 'Corrupt receipt')
        require(receipt['base'] == str(base) and receipt['home'] == str(home)
                and receipt['phase'] in PHASES, 'Wrong receipt target/phase')
        locations(base, home, receipt['report'])
        old = json.loads(decode(receipt['baseline'][str(base / 'production-release.json')]))
        require(set(receipt['baseline']) == {str(p) for p in baseline_paths(base, old)},
                'Incomplete baseline')
        names = set(stage.wrappers(base, Path(receipt['report']['final_control_version'])))
        require(set(receipt['wrappers']) == names == set(receipt['replacements']), 'Incomplete wrapper receipt')
        for name in names:
            original = receipt['wrappers'][name]
            decode(original)
            current = snapshot(base / name)
            replacement = dict(original, data=receipt['replacements'][name])
            require(current in (original, replacement), 'Wrapper drift; manual reconciliation required')
        unchanged(receipt)
        require(dependency_check(base, old) is True, 'Live dependency unknown')
        save_receipt(base, receipt, 'restoring')
        for name in sorted(names):
            unchanged(receipt)
            require(dependency_check(base, old) is True, 'Live dependency unknown')
            original = receipt['wrappers'][name]
            require(snapshot(base / name) in (original, dict(original, data=receipt['replacements'][name])),
                    'Wrapper changed during restore')
            atomic_write(base / name, decode(original))
            require(snapshot(base / name) == original, 'Restore verification failed')
        unchanged(receipt)
        save_receipt(base, receipt, 'restored_artifacts_retained')
        return {'status': 'restored_artifacts_retained', 'artifacts_deleted': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--home', type=Path, required=True)
    parser.add_argument('--stage', type=Path)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--approve-install', action='store_true')
    group.add_argument('--approve-restore', action='store_true')
    args = parser.parse_args(argv)
    if args.approve_install:
        if args.stage is None:
            parser.error('--stage required for installation')
        return install(args.stage, args.base, args.home, approve=True)
    if args.stage is not None:
        parser.error('Restore uses only the durable receipt, not a stage')
    return restore(args.base, args.home, approve=True)


if __name__ == '__main__':
    print(json.dumps(main()))
