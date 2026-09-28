"""Data-only authority for a controls refresh; never imports installation code.

Runtime retains the original stage's report and candidate as provenance inputs.
The root receipt remains baseline authority. Selection/plists and the activation
transaction are intentionally NOT observed here: their owner is Controller.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat

CONTROL_FILES = ('production_launcher.py', 'restart_production.py', 'watchdog.py',
                 'approved_restart_job.py', 'native_identity.py', 'control_refresh.py')
MANAGEMENT = ('restart_production.py', 'watchdog.py', 'approved_restart_job.py')
RECEIPT = 'native-control-refresh-receipt.json'
JOURNAL = 'native-control-refresh-journal.json'
READY = 'native-control-refresh-commit.ready.json'
STAGE_REPORT = 'control-refresh-stage.json'


def require(value, message):
    if not value:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value),
            'Explicit control refresh SHA-256 required')
    return value


def new_wrappers(base, version, pin):
    # No filesystem observation: usable by the preparation-only installer.
    require(isinstance(pin, str) and re.fullmatch('[0-9a-f]{64}', pin),
            'Explicit control refresh SHA-256 required')
    prefix = ('#!/usr/bin/env python3\nimport sys\nfrom pathlib import Path\n'
              f'sys.path.insert(0, {str(version)!r})\nBASE=Path({str(base)!r})\n')
    return {name: prefix + (
        f'import json\nfrom {name[:-3]} import main\n'
        f"result=main(['--base',str(BASE),'--control-refresh-sha256',{pin!r}]+sys.argv[1:])\n"
        "print(json.dumps(result))\n"
        "raise SystemExit(0 if result.get('status') in "
        "('checked','verified','healthy','grace','suspect','cooldown','degraded','busy','restart_requested') else 1)\n"
    ) for name in MANAGEMENT}


def _safe(path, directory=False):
    path = Path(path)
    require(path.is_absolute() and path == path.resolve(), 'Unsafe refresh path')
    ancestors = []
    for item in (path, *path.parents):
        info = item.lstat()
        is_dir = directory or item != path
        require((stat.S_ISDIR(info.st_mode) if is_dir else stat.S_ISREG(info.st_mode))
                and info.st_uid in ({os.getuid()} if item == path else {0, os.getuid()})
                and not info.st_mode & 0o7022, 'Unsafe refresh owner/mode/type')
        ancestors.append((info.st_dev, info.st_ino, info.st_uid, info.st_mode))
    return tuple(ancestors)


def _identity(path):
    info = path.lstat()
    return tuple(getattr(info, k) for k in ('st_dev', 'st_ino', 'st_uid', 'st_mode',
                                          'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def _record(record):
    require(isinstance(record, dict) and set(record) == {'data', 'mode', 'uid'}
            and type(record['mode']) is int and 0 <= record['mode'] <= 0o777
            and not record['mode'] & 0o022 and type(record['uid']) is int
            and record['uid'] == os.getuid(), 'Malformed refresh baseline record')
    return base64.b64decode(record['data'], validate=True)


def load(base, pin, executor, *, read=None):
    """Validate committed deployment and return its publication-edge revalidator.

    An injected reader observes every file, including during unchanged(). Identity
    checks remain local and mandatory; a reader cannot suppress metadata checks.
    """
    require(isinstance(pin, str) and re.fullmatch('[0-9a-f]{64}', pin),
            'Explicit control refresh SHA-256 required')
    base, executor = Path(base), Path(executor)
    _safe(base, True)
    observations, directories = {}, {}
    reader = read or (lambda path: path.read_bytes())

    def observe(path):
        path = Path(path)
        before = (_safe(path), _identity(path))
        raw = reader(path)
        require(before == (_safe(path), _identity(path)), 'Refresh input changed while reading')
        value = (raw, before)
        if path in observations:
            require(observations[path] == value, 'Refresh input changed: ' + str(path))
        observations[path] = value
        return raw

    def bounded(path):
        _safe(path)
        require(path.stat().st_size <= 4 * 1024 * 1024, 'Oversized refresh provenance')
        return observe(path)

    def directory(path):
        ancestry = _safe(path, True)
        info = path.lstat()
        value = (ancestry, info.st_mtime_ns, info.st_ctime_ns,
                 tuple(sorted(p.name for p in path.iterdir())))
        if path in directories:
            require(directories[path] == value, 'Refresh directory changed')
        directories[path] = value

    raw = bounded(base / RECEIPT)
    require(digest(raw) == pin and stat.S_IMODE((base / RECEIPT).stat().st_mode) == 0o444,
            'Refresh receipt pin or mode mismatch')
    receipt = json.loads(raw)
    require(isinstance(receipt, dict) and set(receipt) == {
        'schema_version', 'kind', 'stage', 'stage_sha256', 'original_transaction', 'lock_identity'}
        and type(receipt['schema_version']) is int and receipt['schema_version'] == 1
        and receipt['kind'] == 'native-control-refresh', 'Invalid refresh receipt schema')
    stage = receipt['stage']
    require(isinstance(stage, dict) and set(stage) == {
        'schema_version', 'kind', 'base', 'home', 'root_sha256', 'original_stage',
        'original_stage_sha256', 'version', 'control_sha256', 'app_tree', 'app_identity',
        'launcher', 'launcher_identity'} and type(stage['schema_version']) is int
        and stage['schema_version'] == 1 and stage['kind'] == 'native-control-refresh-stage'
        and digest(encoded(stage)) == receipt['stage_sha256']
        and stage['base'] == str(base) and stage['home'] == str(Path.home()),
        'Invalid refresh stage provenance')
    version = Path(stage['version'])
    require(stage['version'] == str(version) and version.parent == base / 'control-refresh-versions'
            and re.fullmatch('[A-Za-z0-9_-]+', version.name)
            and executor == version / 'restart_production.py'
            and executor.is_absolute() and executor == executor.resolve(),
            'Wrong refreshed executing controller')
    observe(base / 'control.lock')
    require(isinstance(receipt['lock_identity'], list) and len(receipt['lock_identity']) == 2
            and all(type(v) is int for v in receipt['lock_identity'])
            and list(_identity(base / 'control.lock')[:2]) == receipt['lock_identity'],
            'Refresh control lock identity drift')
    original_txn = json.loads(_record(receipt['original_transaction']))
    require(set(original_txn) == {'schema_version', 'transaction', 'sha256'}
            and type(original_txn['schema_version']) is int and original_txn['schema_version'] == 1
            and digest(json.dumps(original_txn['transaction'], sort_keys=True,
                                  separators=(',', ':')).encode()) == original_txn['sha256']
            and original_txn['transaction']['phase'] in {'verified', 'rolled_back'}
            and type(original_txn['transaction']['reload']) is bool
            and isinstance(original_txn['transaction']['operation_id'], str)
            and original_txn['transaction']['authorization'] in {'verified-live-fallback', 'same-release-restart'},
            'Invalid original refresh transaction')
    root_raw = bounded(base / 'native-install-receipt.json')
    require(isinstance(stage['root_sha256'], str)
            and re.fullmatch('[0-9a-f]{64}', stage['root_sha256'])
            and digest(root_raw) == stage['root_sha256'], 'Refresh root receipt mismatch')
    envelope = json.loads(root_raw)
    require(set(envelope) == {'schema_version', 'receipt', 'sha256'}
            and type(envelope['schema_version']) is int and envelope['schema_version'] == 1
            and digest(encoded(envelope['receipt'])) == envelope['sha256'], 'Corrupt root receipt')
    root = envelope['receipt']
    require(root['phase'] == 'installed' and root['base'] == str(base)
            and root['home'] == str(Path.home()), 'Wrong refresh root authority')
    report = root['report']
    old_version = Path(report['final_control_version'])
    app = Path.home() / 'Applications/Verity.app'
    require(report['status'] == 'staged_not_activated' and report['activation_ready'] is False
            and report['final_base'] == str(base) and report['final_bundle'] == str(app)
            and report['final_control_version'] == str(old_version)
            and old_version.parent == base / 'control-versions'
            and re.fullmatch('[A-Za-z0-9_-]+', old_version.name), 'Invalid root deployment')
    for controls, hashes, names in ((old_version, report['control_sha256'], set(CONTROL_FILES) - {'control_refresh.py'}),
                                    (version, stage['control_sha256'], set(CONTROL_FILES))):
        directory(controls)
        require(set(hashes) == names and stat.S_IMODE(controls.stat().st_mode) == 0o555
                and {p.name for p in controls.iterdir()} == names | {'control-receipt.json'},
                'Refresh control membership or directory mode drift')
        require(json.loads(observe(controls / 'control-receipt.json')) == hashes
                and stat.S_IMODE((controls / 'control-receipt.json').stat().st_mode) == 0o444,
                'Refresh control receipt drift')
        for name in names:
            path = controls / name
            require(digest(observe(path)) == hashes[name]
                    and stat.S_IMODE(path.stat().st_mode) == 0o444, 'Refresh control drift')
    original_stage = Path(stage['original_stage'])
    require(stage['original_stage'] == str(original_stage), 'Noncanonical original stage path')
    directory(original_stage)
    raw = bounded(original_stage / 'stage-report.json')
    require(digest(raw) == stage['original_stage_sha256'] and json.loads(raw) == report,
            'Refresh original stage mismatch')
    raw = bounded(original_stage / 'candidate-release.json')
    require(digest(raw) == report['candidate_sha256'], 'Refresh original candidate mismatch')
    candidate = json.loads(raw)
    require(candidate['native_host']['bundle'] == str(app), 'Wrong original candidate app')
    wrappers = set(MANAGEMENT) | {'production_launcher.py'}
    require(set(root['wrappers']) == set(root['replacements']) == wrappers, 'Invalid original wrappers')
    replacements = dict(root['replacements'])
    replacements.update({n: base64.b64encode(text.encode()).decode()
                         for n, text in new_wrappers(base, version, pin).items()})
    for name in wrappers:
        _record(root['wrappers'][name])
        path = base / name
        require(observe(path) == base64.b64decode(replacements[name], validate=True)
                and stat.S_IMODE(path.stat().st_mode) == root['wrappers'][name]['mode'],
                'Refresh installed wrapper drift')
    launcher = base / 'production_launcher.py'
    require(observe(launcher) == _record(stage['launcher'])
            and stage['launcher']['mode'] == root['wrappers'][launcher.name]['mode']
            and list(_identity(launcher)[:2]) == stage['launcher_identity']
            and candidate['native_host']['launcher_sha256'] == digest(observe(launcher)),
            'Refresh stable launcher drift')
    manifest_path = base / 'production-release.json'
    old_raw = _record(root['baseline'][str(manifest_path)])
    old = json.loads(old_raw)
    require(type(old['schema_version']) is int and old['schema_version'] == 2
            and 'native_host' not in old and 'launchd_overrides' not in old
            and set(old['services']) == set(old['labels']) == {'agent', 'webui'}
            and old['labels'] == candidate['labels'] and old['state_dir'] == candidate['state_dir']
            and old.get('launcher_path') == candidate.get('launcher_path')
            and digest(old_raw) == report['selected_sha256'], 'Invalid refresh baseline authority')
    paths = [manifest_path] + [Path(old['services'][s]['plist_path']) for s in ('agent', 'webui')]
    require(len(set(paths)) == 3 and set(root['baseline']) == {str(p) for p in paths},
            'Invalid refresh baseline paths')
    rollback = {}
    for service in ('agent', 'webui'):
        path = Path(old['services'][service]['plist_path'])
        require(path.is_absolute() and path == path.resolve()
                and candidate['services'][service]['plist_path'] == str(path), 'Unsafe baseline plist path')
        raw = _record(root['baseline'][str(path)])
        require(plistlib.loads(raw)['Label'] == old['labels'][service], 'Baseline plist label mismatch')
        rollback[service + '.plist'] = dict(sha256=digest(raw), executable=False)
    for name in wrappers:
        rollback['maintenance/' + name] = dict(sha256=digest(_record(root['wrappers'][name])), executable=False)
    require(rollback == report['rollback_sha256'], 'Refresh rollback provenance mismatch')
    actual, inventory = {}, {}
    for path in (app, *sorted(app.rglob('*'))):
        info = path.lstat()
        relative = str(path.relative_to(app))
        if stat.S_ISDIR(info.st_mode):
            directory(path)
            checksum = None
        else:
            checksum = digest(observe(path))
            inventory[relative] = dict(sha256=checksum, executable=bool(info.st_mode & 0o111))
        actual[relative] = dict(mode=stat.S_IMODE(info.st_mode), uid=info.st_uid, sha256=checksum)
    require(actual == stage['app_tree'] and inventory == candidate['native_host']['inventory']
            and list(_identity(app)[:2]) == stage['app_identity'], 'Refresh app drift')

    def unchanged():
        for path in tuple(directories):
            directory(path)
        for path in tuple(observations):
            observe(path)

    unchanged()
    return receipt, replacements, unchanged
