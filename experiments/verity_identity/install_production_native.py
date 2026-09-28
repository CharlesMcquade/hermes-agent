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
    # Reuse the established schema-2 lock; the shared helper creates absent locks
    # using the caller's umask, which can make later safe recovery impossible.
    safe(base / 'control.lock')
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
    # Reuse the established schema-2 lock; the shared helper creates absent locks
    # using the caller's umask, which can make later safe recovery impossible.
    safe(base / 'control.lock')
    with control_lock(base):
        for name in (UPGRADE_JOURNAL, UPGRADE_RECEIPT):
            safe(base / name, missing=True)
            require(not os.path.lexists(base / name), 'Use explicit upgrade recovery/restore; root receipt is retained')
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


# A single retained hop. These names are protocol constants, never receipt paths.
UPGRADE_JOURNAL = 'native-upgrade-journal.json'
UPGRADE_RECEIPT = 'native-upgrade-receipt.json'
MAX_RECEIPT = 4 * 1024 * 1024
UPGRADE_PHASES = {'copy_controls', 'copy_app', 'retain_v1', 'publish_v2', 'commit',
                  'recover_retain_v2', 'recover_v1_app', 'recovered_v1_artifacts_retained',
                  'legacy_wrappers_restored_artifacts_retained'} | {
    prefix + name for prefix in ('publish_', 'recover_', 'restore_legacy_')
    for name in stage.wrappers(Path('/base'), Path('/version'))}


def bounded_json(path):
    path = safe(path)
    require(path.is_file() and path.stat().st_size <= MAX_RECEIPT, 'Oversized/nonfile receipt')
    with path.open('rb') as stream:
        data = stream.read(MAX_RECEIPT + 1)
    require(len(data) <= MAX_RECEIPT, 'Oversized receipt')
    return json.loads(data)


def tree(path):
    """Content, exact modes, and owners, including directories; no symlink following."""
    path = safe(path)
    require(path.is_dir(), 'Expected artifact directory')
    result = {}
    for item in [path, *sorted(path.rglob('*'))]:
        safe(item)
        info = item.stat()
        result[str(item.relative_to(path))] = dict(
            mode=stat.S_IMODE(info.st_mode), uid=info.st_uid,
            sha256=None if item.is_dir() else stage.digest(item.read_bytes()))
    return result


def sync_directory(path):
    fd = os.open(safe(path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def rename_artifact(source, target):
    safe(source)
    safe(target, missing=True)
    require(not os.path.lexists(target), 'Retained destination exists')
    require(source.stat().st_dev == target.parent.stat().st_dev, 'Cross-filesystem rename')
    os.rename(source, target)
    sync_directory(source.parent)
    if target.parent != source.parent:
        sync_directory(target.parent)


def census_pids(host):
    """Read-only macOS kernel census, not ps (whose own transient PID races itself).

    PID 0 is the kernel and PID 1 is launchd, not a user-installed service host.
    Every other PID, regardless of UID, must have a readable stable kernel identity.
    """
    import ctypes as C
    lib = C.CDLL('/usr/lib/libproc.dylib', use_errno=True)
    lib.proc_listallpids.argtypes = [C.c_void_p, C.c_int]
    lib.proc_listallpids.restype = C.c_int
    capacity = lib.proc_listallpids(None, 0)
    require(0 < capacity < 1000000, 'Unknown process census')
    buffer = (C.c_int * (capacity + 256))()
    count = lib.proc_listallpids(buffer, C.sizeof(buffer))
    require(0 < count < len(buffer), 'Incomplete process census')
    return {pid for pid in buffer[:count] if pid > 1}


def upgrade_dependency_check(base, old):
    # The old two-job check is necessary but cannot exclude independently launched hosts.
    no_live_native_dependency(base, old)
    host = Controller(base).host
    pids = census_pids(host)
    wrapper_paths = {str(base / n) for n in stage.wrappers(base, base / 'control-versions')}
    records = {}
    for pid in pids:
        record = host.process_identity(pid)
        require(record.get('pid') == pid and record.get('start_time') is not None
                and record.get('executable') and record.get('argv'), 'Unknown process identity')
        tokens = [record['executable'], *record['argv']]
        require(all(isinstance(t, str) for t in tokens), 'Unknown process arguments')
        # Conservatively refuse even non-running command references. Do not exclude
        # this controller or other same-UID owners by PID/name alone.
        require(not any('VerityServiceHost' in t or 'Verity.app' in t
                        or 'Verity.upgrade-' in t or str(base / 'control-versions') in t
                        or t in wrapper_paths
                        for t in tokens), 'Independent native/control dependency')
        records[pid] = record
        if re.search(r'python|pypy', Path(record['executable']).name, re.I):
            import sys
            selected = any(record['argv'] == old['services'][role]['argv'] for role in stage.ROLES)
            own_direct_installer = (pid == os.getpid()
                and record['executable'] == str(Path(sys.executable).resolve())
                and str(Path(__file__).resolve()) in record['argv']
                and '-c' not in record['argv'] and '-m' not in record['argv'])
            require(selected or own_direct_installer,
                    'Opaque interpreter may retain installed controls; dependency unknown')
    require(census_pids(host) == pids, 'Process census changed')
    require(all(host.process_identity(pid) == record for pid, record in records.items()),
            'Process identity changed')
    return True


def root_install(base, home, pin):
    require(isinstance(pin, str) and re.fullmatch('[0-9a-f]{64}', pin), 'Explicit root SHA256 required')
    envelope = bounded_json(base / RECEIPT)
    require(stage.digest((base / RECEIPT).read_bytes()) == pin, 'Root receipt pin mismatch')
    require(set(envelope) == {'schema_version', 'receipt', 'sha256'}
            and envelope['schema_version'] == 1, 'Unknown root schema')
    receipt = envelope['receipt']
    require(stage.digest(stage.encoded(receipt)) == envelope['sha256'], 'Corrupt root receipt')
    require(receipt['base'] == str(base) and receipt['home'] == str(home)
            and receipt['phase'] == 'installed', 'Only original installed baseline supported')
    app, version = locations(base, home, receipt['report'])
    old = json.loads(decode(receipt['baseline'][str(base / 'production-release.json')]))
    require(set(receipt['baseline']) == {str(p) for p in baseline_paths(base, old)}, 'Invalid baseline paths')
    expected = stage.wrappers(base, version)
    require(set(receipt['wrappers']) == set(receipt['replacements']) == set(expected), 'Invalid wrappers')
    for name, text in expected.items():
        decode(receipt['wrappers'][name])
        require(base64.b64decode(receipt['replacements'][name], validate=True) == text.encode(),
                'Invalid v1 replacements')
    return receipt, old, app, version


def inspect_stage(root, base, home, runner):
    safe(root)
    for item in root.rglob('*'):
        safe(item)
    report = bounded_json(root / 'stage-report.json')
    require(report['status'] == 'staged_not_activated', 'Incomplete stage')
    locations(base, home, report)
    stage.verify_stage(root, runner=runner)
    version = root / 'control-versions' / Path(report['final_control_version']).name
    require({p.name for p in version.iterdir()} == set(stage.FILES) | {'control-receipt.json'},
            'Extra control files')
    require(bounded_json(version / 'control-receipt.json') == report['control_sha256'], 'Control receipt drift')
    return report, bounded_json(root / 'candidate-release.json')


def upgraded_paths(base, home, report):
    app, version = locations(base, home, report)
    retained = home / 'Applications/Verity.upgrade-v1.app'
    pending = home / 'Applications/Verity.upgrade-v2.app'
    for path in (retained, pending):
        safe(path, missing=True)
    return app, version, retained, pending


def installed_controls(version, report):
    safe(version)
    require(version.stat().st_mode & 0o777 == 0o555, 'Control directory mode drift')
    require({p.name for p in version.iterdir()} == set(stage.FILES) | {'control-receipt.json'}, 'Control set drift')
    for item in version.iterdir():
        safe(item)
        require(item.is_file() and item.stat().st_mode & 0o777 == 0o444, 'Control mode drift')
    require({n: stage.digest((version / n).read_bytes()) for n in stage.FILES} == report['control_sha256'],
            'Installed control drift')
    require(bounded_json(version / 'control-receipt.json') == report['control_sha256'], 'Installed receipt drift')


def upgrade_plan(root, original, base, home, pin, runner):
    receipt, old, app, v1 = root_install(base, home, pin)
    report1, candidate1 = inspect_stage(original, base, home, runner)
    report2, candidate2 = inspect_stage(root, base, home, runner)
    safe(base / 'revoked-releases.json', missing=True)
    for manifest in (old, candidate1, candidate2):
        Controller(base).check_revocation(manifest)
    require(report1 == receipt['report'] and report2['final_control_version'] != str(v1), 'Stage lineage mismatch')
    require(candidate1['native_host']['requirement'] == candidate2['native_host']['requirement'], 'Signer changed')
    require(report1['bootstrap_python'] == report2['bootstrap_python']
            and report1['bootstrap_tmpdir'] == report2['bootstrap_tmpdir'], 'Bootstrap settings changed')
    for staged in (original, root):
        require((staged / 'selected-manifest.json').read_bytes() == decode(receipt['baseline'][str(base / 'production-release.json')]),
                'Stage legacy baseline mismatch')
        for role in stage.ROLES:
            path = old['services'][role]['plist_path']
            require((staged / 'rollback' / (role + '.plist')).read_bytes() == decode(receipt['baseline'][path]),
                    'Stage plist baseline mismatch')
    for name, data in receipt['replacements'].items():
        require((root / 'rollback/maintenance' / name).read_bytes() == base64.b64decode(data, validate=True),
                'Fresh stage did not save v1 wrappers')
        require((original / 'rollback/maintenance' / name).read_bytes() == decode(receipt['wrappers'][name]),
                'Original stage wrapper mismatch')
    installed_controls(v1, report1)
    return dict(root_sha256=pin, original_stage=str(original), new_stage=str(root),
                original_report=report1, new_report=report2,
                original_stage_sha256=stage.digest((original / 'stage-report.json').read_bytes()),
                new_stage_sha256=stage.digest((root / 'stage-report.json').read_bytes()),
                v1_tree=tree(original / 'Verity.app'), v2_tree=tree(root / 'Verity.app'))


def upgrade_journal(base, plan, phase):
    safe(base / UPGRADE_JOURNAL, missing=True)
    if os.path.lexists(base / UPGRADE_JOURNAL):
        previous = read_upgrade(base, UPGRADE_JOURNAL)
        require(previous['plan'] == plan, 'Upgrade journal provenance changed')
    require(phase in UPGRADE_PHASES, 'Unknown upgrade journal phase')
    payload = dict(schema_version=1, kind='one-hop-native-upgrade', plan=plan, phase=phase)
    data = stage.encoded(dict(payload=payload, sha256=stage.digest(stage.encoded(payload))))
    require(len(data) <= MAX_RECEIPT, 'Upgrade journal too large')
    atomic_write(base / UPGRADE_JOURNAL, data)


def read_upgrade(base, filename):
    expected_mode = 0o600 if filename == UPGRADE_JOURNAL else 0o444
    require(stat.S_IMODE(safe(base / filename).stat().st_mode) == expected_mode, 'Upgrade record mode drift')
    envelope = bounded_json(base / filename)
    require(set(envelope) == {'payload', 'sha256'}, 'Unknown upgrade envelope')
    payload = envelope['payload']
    require(stage.digest(stage.encoded(payload)) == envelope['sha256'], 'Corrupt upgrade record')
    require(set(payload) == {'schema_version', 'kind', 'plan', 'phase'}
            and payload['schema_version'] == 1 and payload['kind'] == 'one-hop-native-upgrade', 'Unknown upgrade schema')
    require(payload['phase'] in (UPGRADE_PHASES if filename == UPGRADE_JOURNAL else {'committed'}),
            'Unknown upgrade phase')
    return payload


def upgrade_edge(base, home, plan, runner, dependency_check):
    # Reconstruct destinations and stage semantics every time; never follow payload destinations.
    expected = upgrade_plan(Path(plan['new_stage']), Path(plan['original_stage']), base, home,
                            plan['root_sha256'], runner)
    require(set(plan) == set(expected) | {'v1_identity'}
            and all(plan[k] == v for k, v in expected.items()), 'Upgrade provenance changed')
    receipt, old, _, _ = root_install(base, home, plan['root_sha256'])
    unchanged(receipt)
    require(dependency_check(base, old) is True, 'Native/control dependency unknown')
    # Recheck after observation callbacks as well as before publication.
    unchanged(receipt)
    require(stage.digest((base / RECEIPT).read_bytes()) == plan['root_sha256'], 'Root changed at edge')
    return receipt


def wrapper_records(base, receipt, report):
    return {n: dict(receipt['wrappers'][n], data=base64.b64encode(t.encode()).decode())
            for n, t in stage.wrappers(base, Path(report['final_control_version'])).items()}


def app_identity(path):
    info = safe(path).stat()
    return [info.st_dev, info.st_ino]


def observe_pair(base, home, plan):
    app, version, retained, pending = upgraded_paths(base, home, plan['new_report'])
    observed = {}
    for key, path in [('app', app), ('retained', retained), ('pending', pending)]:
        if not os.path.lexists(path):
            observed[key] = None
            continue
        content = tree(path)
        if content == plan['v1_tree'] and app_identity(path) == plan['v1_identity']:
            observed[key] = 'v1'
        elif content == plan['v2_tree']:
            observed[key] = 'v2'
        else:
            require(False, 'Unknown artifact bytes/identity; manual reconciliation required')
    require((observed['app'], observed['retained'], observed['pending']) in {
        ('v1', None, None), ('v1', None, 'v2'), (None, 'v1', 'v2'), ('v2', 'v1', None)},
        'Unknown artifact arrangement')
    return observed


def complete_upgrade(base, home, plan, receipt, *, wrappers='v2'):
    observed = observe_pair(base, home, plan)
    require(observed == dict(app='v2', retained='v1', pending=None), 'Incomplete upgraded app pair')
    installed_controls(Path(plan['new_report']['final_control_version']), plan['new_report'])
    expected = wrapper_records(base, receipt, plan['new_report']) if wrappers == 'v2' else receipt['wrappers']
    require(all(snapshot(base / n) == record for n, record in expected.items()), 'Incomplete upgraded wrapper pair')


def upgrade(root, base, home, *, original_stage, root_sha256, approve=False,
            runner=stage.run, dependency_check=upgrade_dependency_check):
    require(approve is True, 'Explicit --approve-upgrade required')
    root, original_stage, base, home = map(safe, (root, original_stage, base, home))
    safe(base / 'control.lock')
    with control_lock(base):
        for name in (UPGRADE_JOURNAL, UPGRADE_RECEIPT, 'native-upgrade-commit.ready.json'):
            safe(base / name, missing=True)
            require(not os.path.lexists(base / name), 'One hop already attempted; explicit recovery required')
        plan = upgrade_plan(root, original_stage, base, home, root_sha256, runner)
        app, version, retained, pending = upgraded_paths(base, home, plan['new_report'])
        require(all(not os.path.lexists(p) for p in (version, retained, pending)), 'Upgrade destination exists')
        require(tree(app) == plan['v1_tree'], 'Original app drift')
        runner(['/usr/bin/codesign', '--verify', '--strict', '-R',
                '=' + bounded_json(original_stage / 'candidate-release.json')['native_host']['requirement'], str(app)])
        plan['v1_identity'] = app_identity(app)
        receipt = upgrade_edge(base, home, plan, runner, dependency_check)
        old_wrappers = wrapper_records(base, receipt, plan['original_report'])
        require(all(snapshot(base / n) == r for n, r in old_wrappers.items()), 'Exact v1 wrappers required')
        new_wrappers = wrapper_records(base, receipt, plan['new_report'])
        def edge(phase):
            upgrade_edge(base, home, plan, runner, dependency_check)
            upgrade_journal(base, plan, phase)
            upgrade_edge(base, home, plan, runner, dependency_check)
        edge('copy_controls')
        copy_tree(root / 'control-versions' / version.name, version, controls=True)
        installed_controls(version, plan['new_report'])
        edge('copy_app')
        copy_tree(root / 'Verity.app', pending)
        require(tree(pending) == plan['v2_tree'], 'Copied app drift')
        runner(['/usr/bin/codesign', '--verify', '--strict', '-R',
                '=' + bounded_json(root / 'candidate-release.json')['native_host']['requirement'], str(pending)])
        edge('retain_v1')
        require(observe_pair(base, home, plan) == dict(app='v1', retained=None, pending='v2'), 'App changed before retention')
        rename_artifact(app, retained)
        edge('publish_v2')
        require(observe_pair(base, home, plan) == dict(app=None, retained='v1', pending='v2'), 'App changed before publication')
        rename_artifact(pending, app)
        runner(['/usr/bin/codesign', '--verify', '--strict', '-R',
                '=' + bounded_json(root / 'candidate-release.json')['native_host']['requirement'], str(app)])
        for name, record in new_wrappers.items():
            edge('publish_' + name)
            require(snapshot(base / name) == old_wrappers[name], 'Wrapper changed before upgrade')
            require(observe_pair(base, home, plan) == dict(app='v2', retained='v1', pending=None), 'App pair changed')
            installed_controls(version, plan['new_report'])
            atomic_write(base / name, decode(record))
            require(snapshot(base / name) == record, 'Upgraded wrapper mismatch')
        edge('commit')
        complete_upgrade(base, home, plan, receipt)
        # Atomic publication of a never-rewritten commit record; retain the journal.
        ready = base / 'native-upgrade-commit.ready.json'
        payload = dict(schema_version=1, kind='one-hop-native-upgrade', plan=plan, phase='committed')
        data = stage.encoded(dict(payload=payload, sha256=stage.digest(stage.encoded(payload))))
        require(len(data) <= MAX_RECEIPT, 'Commit receipt too large')
        with ready.open('xb') as stream:
            os.fchmod(stream.fileno(), 0o444)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        sync_directory(base)
        upgrade_edge(base, home, plan, runner, dependency_check)
        complete_upgrade(base, home, plan, receipt)
        rename_artifact(ready, base / UPGRADE_RECEIPT)
        return dict(status='upgraded_not_activated', activated=False,
                    root_sha256=root_sha256, upgrade_sha256=stage.digest(data))


def recover_upgrade(base, home, *, root_sha256, approve=False, runner=stage.run,
                    dependency_check=upgrade_dependency_check):
    require(approve is True, 'Explicit --recover-upgrade required')
    base, home = safe(base), safe(home)
    safe(base / 'control.lock')
    with control_lock(base):
        journal = read_upgrade(base, UPGRADE_JOURNAL)
        plan = journal['plan']
        require(plan['root_sha256'] == root_sha256, 'Recovery root pin mismatch')
        receipt = upgrade_edge(base, home, plan, runner, dependency_check)
        ready = base / 'native-upgrade-commit.ready.json'
        if os.path.lexists(ready):
            prepared_commit = read_upgrade(base, ready.name)
            require(prepared_commit['plan'] == plan, 'Unknown prepared commit provenance')
        if os.path.lexists(base / UPGRADE_RECEIPT):
            committed = read_upgrade(base, UPGRADE_RECEIPT)
            require(committed['phase'] == 'committed' and committed['plan'] == plan, 'Commit lineage mismatch')
            complete_upgrade(base, home, plan, receipt)
            return dict(status='committed_verified', activated=False)
        app, version, retained, pending = upgraded_paths(base, home, plan['new_report'])
        # Unknown partial artifacts are retained and refused, never removed/retried.
        if os.path.lexists(version):
            installed_controls(version, plan['new_report'])
        observed = observe_pair(base, home, plan)
        old = wrapper_records(base, receipt, plan['original_report'])
        new = wrapper_records(base, receipt, plan['new_report'])
        require(all(snapshot(base / n) in (old[n], new[n]) for n in old), 'Unknown wrapper bytes')
        def edge(phase):
            upgrade_edge(base, home, plan, runner, dependency_check)
            observe_pair(base, home, plan)
            upgrade_journal(base, plan, phase)
            upgrade_edge(base, home, plan, runner, dependency_check)
        if observed['app'] == 'v2':
            edge('recover_retain_v2')
            rename_artifact(app, pending)
        if retained.exists():
            edge('recover_v1_app')
            rename_artifact(retained, app)
        for name, record in old.items():
            edge('recover_' + name)
            require(snapshot(base / name) in (record, new[name]), 'Wrapper recovery drift')
            atomic_write(base / name, decode(record))
            require(snapshot(base / name) == record, 'Wrapper recovery mismatch')
        edge('recovered_v1_artifacts_retained')
        require(tree(app) == plan['v1_tree'] and app_identity(app) == plan['v1_identity'], 'v1 recovery mismatch')
        return dict(status='recovered_v1_artifacts_retained', artifacts_deleted=False)


def verified_upgraded_return(base, root_sha256, upgrade_sha256):
    require((base / 'activation-transaction.json').exists(), 'A verified upgraded return receipt is required')
    bounded_json(base / 'activation-transaction.json')
    txn = Controller(base).read_transaction()
    require(txn is not None and txn.get('phase') == 'verified' and txn.get('reload') is True
            and txn.get('operation') == 'return-retained-baseline'
            and txn.get('baseline_sha256') == root_sha256
            and txn.get('upgrade_sha256') == upgrade_sha256,
            'A verified upgraded return receipt is required')
    return snapshot(base / 'activation-transaction.json')


def restore_upgraded_wrappers(base, home, *, root_sha256, upgrade_sha256, approve=False,
                              runner=stage.run, dependency_check=upgrade_dependency_check):
    require(approve is True, 'Explicit --restore-upgraded-wrappers required')
    base, home = safe(base), safe(home)
    safe(base / 'control.lock')
    with control_lock(base):
        require(isinstance(upgrade_sha256, str) and re.fullmatch('[0-9a-f]{64}', upgrade_sha256), 'Explicit upgrade SHA256 required')
        committed = read_upgrade(base, UPGRADE_RECEIPT)
        require(stage.digest((base / UPGRADE_RECEIPT).read_bytes()) == upgrade_sha256
                and committed['phase'] == 'committed', 'Upgrade pin mismatch')
        plan = committed['plan']
        require(plan['root_sha256'] == root_sha256, 'Restore root pin mismatch')
        receipt = upgrade_edge(base, home, plan, runner, dependency_check)
        returned = verified_upgraded_return(base, root_sha256, upgrade_sha256)
        def check_return():
            require(verified_upgraded_return(base, root_sha256, upgrade_sha256) == returned,
                    'Verified return receipt changed')
            require(stage.digest((base / UPGRADE_RECEIPT).read_bytes()) == upgrade_sha256,
                    'Committed upgrade receipt changed')
        journal = read_upgrade(base, UPGRADE_JOURNAL)
        require(journal['plan'] == plan, 'Journal lineage mismatch')
        new = wrapper_records(base, receipt, plan['new_report'])
        for name, record in receipt['wrappers'].items():
            require(snapshot(base / name) in (new[name], record), 'Unknown postreturn wrapper')
        for name, record in receipt['wrappers'].items():
            upgrade_edge(base, home, plan, runner, dependency_check)
            require(observe_pair(base, home, plan) == dict(app='v2', retained='v1', pending=None), 'Postreturn app drift')
            installed_controls(Path(plan['new_report']['final_control_version']), plan['new_report'])
            check_return()
            upgrade_journal(base, plan, 'restore_legacy_' + name)
            upgrade_edge(base, home, plan, runner, dependency_check)
            check_return()
            require(snapshot(base / name) in (new[name], record), 'Postreturn wrapper drift')
            atomic_write(base / name, decode(record))
            require(snapshot(base / name) == record, 'Postreturn wrapper mismatch')
        upgrade_edge(base, home, plan, runner, dependency_check)
        complete_upgrade(base, home, plan, receipt, wrappers='legacy')
        check_return()
        upgrade_journal(base, plan, 'legacy_wrappers_restored_artifacts_retained')
        return dict(status='legacy_wrappers_restored_artifacts_retained', artifacts_deleted=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--home', type=Path, required=True)
    parser.add_argument('--stage', type=Path)
    parser.add_argument('--original-stage', type=Path)
    parser.add_argument('--root-sha256')
    parser.add_argument('--upgrade-sha256')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--approve-install', action='store_true')
    group.add_argument('--approve-restore', action='store_true')
    group.add_argument('--approve-upgrade', action='store_true')
    group.add_argument('--recover-upgrade', action='store_true')
    group.add_argument('--restore-upgraded-wrappers', action='store_true')
    args = parser.parse_args(argv)
    if args.approve_upgrade or args.recover_upgrade or args.restore_upgraded_wrappers:
        if not args.root_sha256:
            parser.error('--root-sha256 is required')
        common = dict(root_sha256=args.root_sha256, approve=True)
        if args.approve_upgrade:
            if args.stage is None or args.original_stage is None or args.upgrade_sha256 is not None:
                parser.error('Upgrade requires --stage and --original-stage, not --upgrade-sha256')
            return upgrade(args.stage, args.base, args.home, original_stage=args.original_stage, **common)
        if args.stage is not None or args.original_stage is not None:
            parser.error('Recovery/restore uses retained stage references, not supplied stages')
        if args.restore_upgraded_wrappers:
            if args.upgrade_sha256 is None:
                parser.error('--upgrade-sha256 is required')
            return restore_upgraded_wrappers(args.base, args.home, upgrade_sha256=args.upgrade_sha256, **common)
        if args.upgrade_sha256 is not None:
            parser.error('Recovery takes only --root-sha256')
        return recover_upgrade(args.base, args.home, **common)
    if any(x is not None for x in (args.original_stage, args.root_sha256, args.upgrade_sha256)):
        parser.error('Upgrade arguments require an upgrade operation')
    if args.approve_install:
        if args.stage is None:
            parser.error('--stage required for installation')
        return install(args.stage, args.base, args.home, approve=True)
    if args.stage is not None:
        parser.error('Restore uses only the durable receipt, not a stage')
    return restore(args.base, args.home, approve=True)


if __name__ == '__main__':
    print(json.dumps(main()))
