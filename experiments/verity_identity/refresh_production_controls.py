"""Explicit controls-only refresh; no compiler, signer, census or service mutation.

The original stage remains required for offline app provenance. Recovery retains
all evidence, restores v1 management wrappers, and removes the schema fence LAST.
Postactivation restoration instead requires a real verified return transaction.
The advisory control lock is cooperation, not protection against hostile UID peers.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import stat
import tempfile

import install_production_native as original
import stage_production_native as native_stage
from restart_production import atomic_write, control_lock, require
from control_refresh import CONTROL_FILES, MANAGEMENT, RECEIPT, JOURNAL, READY, STAGE_REPORT, new_wrappers

CONTROL = native_stage.CONTROL
TRANSACTION = 'activation-transaction.json'
encoded = native_stage.encoded
digest = native_stage.digest
safe = original.safe
snapshot = original.snapshot
decode = original.decode


def pin(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'Explicit lowercase SHA256 required')
    return value


def raw(path):
    path = safe(path)
    require(path.is_file() and path.stat().st_size <= original.MAX_RECEIPT, 'Oversized/nonfile input')
    data = path.read_bytes()
    require(len(data) <= original.MAX_RECEIPT, 'Oversized input')
    return data


def sealed_write(path, data):
    """Publish mode 0444 at rename, never a briefly writable authority record."""
    safe(path, missing=True)
    require(not path.exists(), 'Sealed publication already exists')
    fd, name = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o444)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        original.sync_directory(path.parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def version_path(base, name):
    require(isinstance(name, str) and re.fullmatch('[A-Za-z0-9_-]+', name), 'Unsafe version name')
    return safe(base / 'control-refresh-versions' / name, missing=True)


def v1_records(receipt):
    return {n: dict(receipt['wrappers'][n], data=receipt['replacements'][n]) for n in MANAGEMENT}


def immutable_baseline(base, home, root_sha256, original_stage):
    receipt, old, app, version = original.root_install(base, home, pin(root_sha256))
    source = safe(original_stage)
    report = json.loads(raw(source / 'stage-report.json'))
    require(report == receipt['report'] and report['status'] == 'staged_not_activated', 'Original stage lineage mismatch')
    candidate_raw = raw(source / 'candidate-release.json')
    require(digest(candidate_raw) == report['candidate_sha256'], 'Candidate hash mismatch')
    candidate = json.loads(candidate_raw)
    require(native_stage.inventory(app) == candidate['native_host']['inventory'], 'App inventory drift')
    require(original.tree(app) == original.tree(source / 'Verity.app'), 'App metadata drift')
    require(raw(source / 'selected-manifest.json') == decode(receipt['baseline'][str(base / 'production-release.json')]), 'Original selection mismatch')
    for role in native_stage.ROLES:
        require(raw(source / 'rollback' / (role + '.plist')) == decode(receipt['baseline'][old['services'][role]['plist_path']]), 'Original plist mismatch')
    for name, record in receipt['wrappers'].items():
        require(raw(source / 'rollback/maintenance' / name) == decode(record), 'Original wrapper mismatch')
    original.installed_controls(version, report)
    launcher = dict(receipt['wrappers']['production_launcher.py'], data=receipt['replacements']['production_launcher.py'])
    require(snapshot(base / 'production_launcher.py') == launcher, 'Stable launcher drift')
    for n in (original.UPGRADE_JOURNAL, original.UPGRADE_RECEIPT):
        safe(base / n, missing=True)
        require(not (base / n).exists(), 'Upgrade lineage unsupported')
    return receipt, old, app


def legacy_selected(receipt):
    for path, record in receipt['baseline'].items():
        require(snapshot(Path(path)) == record, 'Legacy selection/plist drift')


def controls(path, hashes, *, partial=False):
    safe(path)
    require(set(hashes) == set(CONTROL_FILES), 'Control hash set mismatch')
    allowed = set(CONTROL_FILES) | {'control-receipt.json'}
    found = {p.name for p in path.iterdir()}
    require(found <= allowed if partial else found == allowed, 'Control membership drift')
    require(stat.S_IMODE(path.stat().st_mode) in ({0o700, 0o555} if partial else {0o555}), 'Control directory mode drift')
    for name in found:
        item = safe(path / name)
        require(item.is_file() and stat.S_IMODE(item.stat().st_mode) in ({0o600, 0o444} if partial else {0o444}), 'Control mode drift')
        data = raw(item)
        require(json.loads(data) == hashes if name == 'control-receipt.json' else digest(data) == hashes[name], 'Control bytes drift')


def stage(root, base, home, *, original_stage, root_sha256, version_name):
    root, base, home = safe(root, missing=True), safe(base), safe(home)
    require(not root.exists(), 'Stage must be new')
    safe(root.parent)
    version = version_path(base, version_name)
    require(not version.exists(), 'Version already exists')
    receipt, _, app = immutable_baseline(base, home, root_sha256, Path(original_stage))
    protected = (app, Path(receipt['report']['final_control_version']), safe(original_stage), safe(CONTROL))
    require(not any(root == p or root.is_relative_to(p) for p in protected)
            and not root.is_relative_to(version) and not version.is_relative_to(root),
            'Stage overlaps immutable or planned artifacts')
    legacy_selected(receipt)
    require(all(snapshot(base / n) == r for n, r in v1_records(receipt).items()), 'Installed wrapper drift')
    hashes = {n: digest(raw(CONTROL / n)) for n in CONTROL_FILES}
    report = dict(schema_version=1, kind='native-control-refresh-stage', base=str(base), home=str(home),
                  root_sha256=root_sha256, original_stage=str(safe(original_stage)),
                  original_stage_sha256=digest(raw(Path(original_stage) / 'stage-report.json')),
                  version=str(version), control_sha256=hashes, app_tree=original.tree(app),
                  app_identity=original.app_identity(app), launcher=snapshot(base / 'production_launcher.py'),
                  launcher_identity=original.app_identity(base / 'production_launcher.py'))
    root.mkdir(mode=0o700)
    source = root / 'controls'
    source.mkdir(mode=0o700)
    for name in CONTROL_FILES:
        data = raw(CONTROL / name)
        require(digest(data) == hashes[name], 'Control source changed')
        sealed_write(source / name, data)
    sealed_write(source / 'control-receipt.json', encoded(hashes))
    source.chmod(0o555)
    original.sync_directory(source)
    sealed_write(root / STAGE_REPORT, encoded(report))
    inspect(root, base, home, digest(encoded(report)), root_sha256)
    return report


def inspect(root, base, home, stage_sha256, root_sha256):
    data = raw(root / STAGE_REPORT)
    require(digest(data) == pin(stage_sha256), 'Stage pin mismatch')
    report = json.loads(data)
    require(set(report) == {'schema_version', 'kind', 'base', 'home', 'root_sha256', 'original_stage',
            'original_stage_sha256', 'version', 'control_sha256', 'app_tree', 'app_identity', 'launcher', 'launcher_identity'}
            and type(report['schema_version']) is int and report['schema_version'] == 1
            and report['kind'] == 'native-control-refresh-stage', 'Unknown stage schema')
    require(data == encoded(report), 'Noncanonical stage report')
    require(report['base'] == str(base) and report['home'] == str(home) and report['root_sha256'] == pin(root_sha256), 'Stage target mismatch')
    version = version_path(base, Path(report['version']).name)
    require(str(version) == report['version'], 'Wrong version destination')
    receipt, old, app = immutable_baseline(base, home, root_sha256, Path(report['original_stage']))
    require(digest(raw(Path(report['original_stage']) / 'stage-report.json')) == report['original_stage_sha256'], 'Original stage changed')
    require(original.tree(app) == report['app_tree'] and original.app_identity(app) == report['app_identity'], 'App changed')
    require(snapshot(base / 'production_launcher.py') == report['launcher'] and
            original.app_identity(base / 'production_launcher.py') == report['launcher_identity'], 'Launcher changed')
    controls(root / 'controls', report['control_sha256'])
    return report, receipt, old


def transaction(data, schema, refresh_pin=None):
    envelope = json.loads(data)
    fields = {'schema_version', 'transaction', 'sha256'} | ({'control_refresh_sha256'} if schema == 2 else set())
    require(set(envelope) == fields and type(envelope['schema_version']) is int and envelope['schema_version'] == schema, 'Wrong transaction schema')
    txn = envelope['transaction']
    require(digest(json.dumps(txn, sort_keys=True, separators=(',', ':')).encode()) == envelope['sha256'], 'Corrupt transaction')
    require(txn['phase'] in {'prepared', 'verified', 'rollback_started', 'rolled_back', 'rollback_failed'}
            and type(txn['reload']) is bool and isinstance(txn['operation_id'], str)
            and txn['authorization'] in {'verified-live-fallback', 'same-release-restart'}, 'Invalid transaction')
    if schema == 2:
        require(envelope['control_refresh_sha256'] == pin(refresh_pin), 'Transaction refresh mismatch')
    return envelope


def fence(receipt):
    original_txn = transaction(decode(receipt['original_transaction']), 1)
    return dict(original_txn, schema_version=2, control_refresh_sha256=digest(encoded(receipt)))


def journal(base, receipt, phase, proof=None):
    payload = dict(schema_version=1, receipt=receipt, phase=phase, return_proof=proof)
    data = encoded(dict(payload=payload, sha256=digest(encoded(payload))))
    require(len(data) <= original.MAX_RECEIPT, 'Journal too large')
    safe(base / JOURNAL, missing=True)
    atomic_write(base / JOURNAL, data)


def retained(root, base, home, stage_sha256, root_sha256):
    report, baseline, old = inspect(root, base, home, stage_sha256, root_sha256)
    require(stat.S_IMODE(safe(base / JOURNAL).stat().st_mode) == 0o600, 'Journal mode drift')
    envelope = json.loads(raw(base / JOURNAL))
    require(set(envelope) == {'payload', 'sha256'} and digest(encoded(envelope['payload'])) == envelope['sha256'], 'Corrupt refresh journal')
    payload = envelope['payload']
    require(set(payload) == {'schema_version', 'receipt', 'phase', 'return_proof'} and payload['schema_version'] == 1, 'Unknown journal')
    require(payload['phase'] in {'prepared', 'ready', 'fenced', 'committed', 'recovering', 'recovered', 'restoring', 'restored'} | {'publish_' + n for n in MANAGEMENT}, 'Unknown journal phase')
    receipt = payload['receipt']
    require(set(receipt) == {'schema_version', 'kind', 'stage', 'stage_sha256', 'original_transaction', 'lock_identity'}
            and receipt['schema_version'] == 1 and receipt['kind'] == 'native-control-refresh'
            and receipt['stage'] == report and receipt['stage_sha256'] == stage_sha256, 'Refresh receipt lineage mismatch')
    require(original.app_identity(base / 'control.lock') == receipt['lock_identity'], 'Control lock changed')
    require(transaction(decode(receipt['original_transaction']), 1)['transaction']['phase'] in {'verified', 'rolled_back'}, 'Original transaction not terminal')
    for name in (READY, RECEIPT):
        safe(base / name, missing=True)
        if (base / name).exists():
            require(stat.S_IMODE((base / name).stat().st_mode) == 0o444 and raw(base / name) == encoded(receipt), 'Retained receipt drift')
    return receipt, baseline, old, payload


def edge(root, base, home, stage_sha256, root_sha256, receipt, *, postreturn=False, proof=None, pending_proof=False):
    actual, baseline, old, payload = retained(root, base, home, stage_sha256, root_sha256)
    require(actual == receipt, 'Journal changed')
    legacy_selected(baseline)
    before = receipt['original_transaction']
    current = snapshot(base / TRANSACTION)
    if postreturn:
        require(proof is not None and payload['return_proof'] == (None if pending_proof else proof), 'Return proof changed')
        require(current in (proof, before), 'Return transaction changed')
    else:
        require(payload['return_proof'] is None, 'Use postactivation restore')
        allowed_fence = dict(before, data=base64.b64encode(encoded(fence(receipt))).decode())
        require(current in (before, allowed_fence), 'Activation occurred or transaction changed')
    replacements = {n: dict(baseline['wrappers'][n], data=base64.b64encode(t.encode()).decode())
                    for n, t in new_wrappers(base, Path(receipt['stage']['version']), digest(encoded(receipt))).items()}
    require(set(replacements) == set(MANAGEMENT), 'Management wrapper set mismatch')
    for n, old_record in v1_records(baseline).items():
        require(snapshot(base / n) in (old_record, replacements[n]), 'Management wrapper drift')
    ready = (base / READY).exists()
    version = Path(receipt['stage']['version'])
    if version.exists():
        controls(version, receipt['stage']['control_sha256'], partial=not ready)
    else:
        require(not ready, 'Missing ready controls')
    if current != before or any(snapshot(base / n) != r for n, r in v1_records(baseline).items()):
        require(ready, 'Missing publication readiness')
    return baseline, old, replacements


def install(root, base, home, *, stage_sha256, root_sha256, approve=False):
    require(approve is True, 'Explicit --approve required')
    root, base, home = safe(root), safe(base), safe(home)
    lock = original.app_identity(safe(base / 'control.lock'))
    with control_lock(base, expected_identity=tuple(lock)):
        require(original.app_identity(base / 'control.lock') == lock, 'Control lock changed')
        report, baseline, _ = inspect(root, base, home, stage_sha256, root_sha256)
        legacy_selected(baseline)
        for name in (JOURNAL, READY, RECEIPT):
            safe(base / name, missing=True)
            require(not (base / name).exists(), 'Previous refresh exists')
        version = Path(report['version'])
        require(not version.exists(), 'Version already exists')
        require(all(snapshot(base / n) == r for n, r in v1_records(baseline).items()), 'Installed wrapper drift')
        before = snapshot(base / TRANSACTION)
        require(transaction(decode(before), 1)['transaction']['phase'] in {'verified', 'rolled_back'}, 'Terminal activation required')
        receipt = dict(schema_version=1, kind='native-control-refresh', stage=report,
                       stage_sha256=stage_sha256, original_transaction=before, lock_identity=lock)
        journal(base, receipt, 'prepared')
        check = lambda: edge(root, base, home, stage_sha256, root_sha256, receipt)
        check()
        if not version.parent.exists():
            version.parent.mkdir(mode=0o700)
            original.sync_directory(base)
        original.copy_tree(root / 'controls', version, controls=True)
        controls(version, report['control_sha256'])
        check()
        sealed_write(base / READY, encoded(receipt))
        journal(base, receipt, 'ready')
        check()
        atomic_write(base / TRANSACTION, encoded(fence(receipt)))
        journal(base, receipt, 'fenced')
        for n in MANAGEMENT:
            _, _, replacements = check()
            controls(version, report['control_sha256'])
            journal(base, receipt, 'publish_' + n)
            check()
            atomic_write(base / n, decode(replacements[n]))
            require(snapshot(base / n) == replacements[n], 'Wrapper publication failed')
        check()
        controls(version, report['control_sha256'])
        journal(base, receipt, 'committed')
        _, _, replacements = check()
        require(all(snapshot(base / n) == r for n, r in replacements.items()), 'Incomplete wrapper publication')
        sealed_write(base / RECEIPT, encoded(receipt))  # Commit authority LAST.
        require(raw(base / RECEIPT) == encoded(receipt), 'Commit readback failed')
        return dict(status='installed', control_refresh_sha256=digest(encoded(receipt)), activated=False)


def recover(root, base, home, *, stage_sha256, root_sha256, approve=False):
    return undo(root, base, home, stage_sha256=stage_sha256, root_sha256=root_sha256, approve=approve)


def restore(root, base, home, *, stage_sha256, root_sha256, refresh_sha256, approve=False,
            dependency_check=original.no_live_native_dependency):
    return undo(root, base, home, stage_sha256=stage_sha256, root_sha256=root_sha256,
                approve=approve, refresh_sha256=pin(refresh_sha256), dependency_check=dependency_check)


def undo(root, base, home, *, stage_sha256, root_sha256, approve, refresh_sha256=None, dependency_check=None):
    require(approve is True, 'Explicit --approve required')
    root, base, home = safe(root), safe(base), safe(home)
    lock = original.app_identity(safe(base / 'control.lock'))
    with control_lock(base, expected_identity=tuple(lock)):
        require(original.app_identity(base / 'control.lock') == lock, 'Control lock changed')
        receipt, baseline, old, payload = retained(root, base, home, stage_sha256, root_sha256)
        postreturn = refresh_sha256 is not None
        proof = payload['return_proof']
        version = Path(receipt['stage']['version'])
        if version.exists():
            controls(version, receipt['stage']['control_sha256'], partial=not (base / READY).exists())
        elif (base / READY).exists():
            require(False, 'Missing ready controls')
        if postreturn:
            require(raw(base / RECEIPT) == encoded(receipt) and digest(encoded(receipt)) == refresh_sha256, 'Refresh pin mismatch')
            if proof is None:
                proof = snapshot(base / TRANSACTION)
            txn = transaction(decode(proof), 2, refresh_sha256)['transaction']
            require(txn['phase'] == 'verified' and txn['reload'] is True
                    and txn.get('operation') == 'return-retained-baseline'
                    and txn.get('baseline_sha256') == root_sha256
                    and txn.get('control_refresh_sha256') == refresh_sha256, 'Verified exact return required')
            require(snapshot(base / TRANSACTION) in (proof, receipt['original_transaction']) if payload['return_proof'] is not None
                    else snapshot(base / TRANSACTION) == proof, 'Return proof no longer current')
            legacy_selected(baseline)
            require(dependency_check(base, old) is True, 'Legacy dependency unknown')
            edge(root, base, home, stage_sha256, root_sha256, receipt, postreturn=True,
                 proof=proof, pending_proof=payload['return_proof'] is None)
            # Preserve the actual transaction before touching any management wrapper.
            if payload['return_proof'] is None:
                journal(base, receipt, 'restoring', proof)
        check = lambda: edge(root, base, home, stage_sha256, root_sha256, receipt, postreturn=postreturn, proof=proof)
        check()
        journal(base, receipt, 'restoring' if postreturn else 'recovering', proof)
        for n, record in v1_records(baseline).items():
            check()
            if postreturn:
                require(dependency_check(base, old) is True, 'Legacy dependency unknown')
                check()
            if snapshot(base / n) != record:
                atomic_write(base / n, decode(record))
            require(snapshot(base / n) == record, 'Wrapper restore readback failed')
        check()
        if postreturn:
            require(dependency_check(base, old) is True, 'Legacy dependency unknown')
            check()
        # Journal final intent before the final authority write. Never manufacture
        # a successful future transaction, never delete the actual return proof.
        journal(base, receipt, 'restored' if postreturn else 'recovered', proof)
        check()
        if postreturn:
            require(dependency_check(base, old) is True, 'Legacy dependency unknown')
            check()
        require(all(snapshot(base / n) == r for n, r in v1_records(baseline).items()), 'Incomplete restoration')
        atomic_write(base / TRANSACTION, decode(receipt['original_transaction']))
        require(snapshot(base / TRANSACTION) == receipt['original_transaction'], 'Original transaction restore failed')
        return dict(status='restored_artifacts_retained' if postreturn else 'recovered_artifacts_retained', artifacts_deleted=False)


class Once(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        require(getattr(namespace, self.dest, None) is None, 'Duplicate argument: ' + str(option_string))
        setattr(namespace, self.dest, values)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('stage', 'install', 'recover', 'restore'))
    for name in ('stage', 'base', 'home', 'root-sha256'):
        parser.add_argument('--' + name, required=True, action=Once)
    for name in ('original-stage', 'version-name', 'stage-sha256', 'refresh-sha256'):
        parser.add_argument('--' + name, action=Once)
    parser.add_argument('--approve', action='store_true')
    args = parser.parse_args(argv)
    common = dict(root_sha256=args.root_sha256)
    if args.operation == 'stage':
        require(args.original_stage is not None and args.version_name is not None
                and args.stage_sha256 is None and args.refresh_sha256 is None, 'Stage arguments required')
        return stage(Path(args.stage), Path(args.base), Path(args.home), original_stage=Path(args.original_stage), version_name=args.version_name, **common)
    require(args.original_stage is None and args.version_name is None, 'Unexpected staging arguments')
    require(args.stage_sha256 is not None, 'Explicit stage SHA256 required')
    common.update(stage_sha256=args.stage_sha256, approve=args.approve)
    if args.operation == 'restore':
        require(args.refresh_sha256 is not None, 'Explicit refresh SHA256 required')
        common['refresh_sha256'] = args.refresh_sha256
    else:
        require(args.refresh_sha256 is None, 'Refresh pin only valid for restore')
    return {'install': install, 'recover': recover, 'restore': restore}[args.operation](Path(args.stage), Path(args.base), Path(args.home), **common)


if __name__ == '__main__':
    print(json.dumps(main(), sort_keys=True))
