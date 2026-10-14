#!/usr/bin/env python3
"""Upgrade already-native management controls without restarting a service.

This is NOT the legacy-to-native installer, a launcher migration, or a drift
re-sealer. Current admission must pass. Source is six genuine Git objects at an
explicit commit. Plan/apply/recover retain exact old bytes and fail on unknown
writers. The signed app, stable launcher, selector and plists are never changed.
"""
import argparse
import base64
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

from typing import TypedDict

class FileRecord(TypedDict):
    data: str
    mode: int
    uid: int

FILES = ('production_launcher.py', 'restart_production.py', 'watchdog.py',
         'approved_restart_job.py', 'native_identity.py', 'control_refresh.py')
WRAPPERS = ('restart_production.py', 'watchdog.py', 'approved_restart_job.py')
RECEIPT = 'native-control-refresh-receipt.json'
JOURNAL = 'native-control-refresh-journal.json'
TRANSACTION = 'activation-transaction.json'
TARGETS = (TRANSACTION, *WRAPPERS, JOURNAL, RECEIPT)
MAX_FILE_BYTES = 64 * 1024 * 1024
# Old/new backups and guards are base64 embedded; this is NOT a file limit.
MAX_PLAN_BYTES = 256 * 1024 * 1024


def require(ok, message):
    if not ok:
        raise ValueError(message)


def encoded(obj):
    return (json.dumps(obj, indent=2, sort_keys=True) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def record(path, *, max_bytes=None) -> FileRecord:
    """No-follow, bounded read; reject inode/content metadata changing mid-read."""
    max_bytes = MAX_FILE_BYTES if max_bytes is None else max_bytes
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid()
                and not s.st_mode & 0o022 and s.st_size <= max_bytes,
                'Unsafe input file: ' + str(path))
        with os.fdopen(fd, 'rb', closefd=False) as f:
            raw = f.read(max_bytes + 1)
        t = os.fstat(fd)
        require((s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
                == (t.st_dev, t.st_ino, t.st_size, t.st_mtime_ns, t.st_ctime_ns)
                and path.lstat().st_ino == s.st_ino and len(raw) == s.st_size,
                'Input changed while read: ' + str(path))
        return FileRecord(data=base64.b64encode(raw).decode(), mode=stat.S_IMODE(s.st_mode), uid=s.st_uid)
    finally:
        os.close(fd)


def data(rec, *, max_bytes=None):
    max_bytes = MAX_FILE_BYTES if max_bytes is None else max_bytes
    require(isinstance(rec, dict) and set(rec) == {'data', 'mode', 'uid'}
            and rec['uid'] == os.getuid() and type(rec['mode']) is int
            and not rec['mode'] & 0o022, 'Invalid file record')
    require(isinstance(rec['data'], str)
            and len(rec['data']) <= 4 * ((max_bytes + 2) // 3), 'File record too large or malformed')
    raw = base64.b64decode(rec['data'], validate=True)
    require(len(raw) <= max_bytes, 'File record too large')
    return raw


def packed(raw, mode: int=0o444) -> FileRecord:
    return FileRecord(data=base64.b64encode(raw).decode(), mode=mode, uid=os.getuid())


def safe_dir(path):
    p = Path(path)
    require(p.is_absolute() and p == p.resolve(), 'Noncanonical directory')
    s = p.lstat()
    require(stat.S_ISDIR(s.st_mode) and s.st_uid == os.getuid()
            and not s.st_mode & 0o022, 'Unsafe directory: ' + str(p))
    return p


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic(path, rec, *, max_bytes=None):
    raw = data(rec, max_bytes=max_bytes)
    fd, tmp = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            os.fchmod(f.fileno(), rec['mode'])
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        sync_dir(path.parent)
        require(record(path, max_bytes=max_bytes) == rec, 'Publication readback failed')
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


@contextmanager
def locked(base):
    path = base / 'control.lock'
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid()
                and not s.st_mode & 0o022, 'Unsafe control lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        t = path.lstat()
        require((s.st_dev, s.st_ino) == (t.st_dev, t.st_ino), 'Control lock replaced')
        yield
        t = path.lstat()
        require((s.st_dev, s.st_ino) == (t.st_dev, t.st_ino), 'Control lock changed')
    finally:
        os.close(fd)


def helper(version, expression, arguments):
    # No app imports or inherited provider environment. HOME is required by the
    # installed admission contract; this subprocess only loads management code.
    program = 'import sys,json; from pathlib import Path; sys.path.insert(0,sys.argv[1]); ' + expression
    env = dict(HOME=str(Path.home()), PATH='/usr/bin:/bin:/usr/sbin:/sbin',
               PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
    run = subprocess.run([sys.executable, '-I', '-B', '-c', program, str(version), *map(str, arguments)],
                         env=env, cwd=version, capture_output=True, text=True, timeout=90)
    require(run.returncode == 0, 'Management admission/generation failed: ' + run.stderr[-1200:])
    return json.loads(run.stdout)


def admit(base, pin, version):
    # Do not execute a bundle to ask whether that same bundle is trustworthy.
    raw = data(record(base / RECEIPT))
    require(sha(raw) == pin, 'Management admission receipt pin mismatch')
    stage = json.loads(raw)['stage']
    require(stage['version'] == str(version), 'Management admission version mismatch')
    verify_bundle(version, stage['control_sha256'])
    return helper(version, 'from control_refresh import load; '
                  'load(Path(sys.argv[2]),sys.argv[3],Path(sys.argv[1])/"restart_production.py"); '
                  'print(json.dumps({"admitted":True}))', [base, pin])


def wrappers(base, pin, version, import_from):
    return helper(import_from, 'from control_refresh import new_wrappers; '
                  'print(json.dumps(new_wrappers(Path(sys.argv[2]),Path(sys.argv[3]),sys.argv[4])))',
                  [base, version, pin])


def source_git(repo, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)
    return subprocess.run(['git', '--no-replace-objects', '-c', 'core.fsmonitor=false',
                           '-c', 'core.hooksPath=' + os.devnull, '-C', str(repo), *args],
                          env=env, capture_output=True, timeout=30)


def git_file(repo, commit, name):
    p = source_git(repo, 'show', commit + ':scripts/production_control/' + name)
    require(p.returncode == 0, 'Missing control source object: ' + name)
    return p.stdout


def guards(base):
    manifest = json.loads(data(record(base / 'production-release.json')))
    names = [base / 'production-release.json', base / 'production_launcher.py']
    names += [Path(manifest['services'][s]['plist_path']) for s in ('agent', 'webui')]
    return {str(p): record(p) for p in names}


def check_guards(values):
    require(all(record(Path(p)) == v for p, v in values.items()),
            'Untouched selector/launcher/plist changed; stop and reconcile')


def build_reseal_plan(base, repo, commit, version_name, output, current_pin):
    """Approved recovery for control.lock st_dev rotation (volume re-id on reboot).

    NOT a drift blessing for content: every control module byte must still match
    the currently trusted receipt exactly. Only the lock identity datum is
    refreshed, because st_dev is an OS-assigned volume identifier that rotates
    legitimately on reboot while inode + module bytes stay stable. Publishes a
    new receipt/wrappers/journal/transaction with the LIVE (dev, ino) under the
    same locked, CAS-guarded, atomic publication path as an ordinary upgrade.
    """
    base, repo = safe_dir(base), safe_dir(repo)
    require(re.fullmatch('[0-9a-f]{40}', commit) is not None, 'Exact source commit required')
    obj = source_git(repo, 'cat-file', '-t', commit)
    require(obj.returncode == 0 and obj.stdout.strip() == b'commit', 'Source object is not a genuine commit')
    require(re.fullmatch('[A-Za-z0-9_-]+', version_name) is not None, 'Invalid version name')
    require(re.fullmatch('[0-9a-f]{64}', current_pin) is not None, 'Exact old receipt pin required')
    output = Path(output)
    safe_dir(output.parent)
    output.mkdir(mode=0o700)
    with locked(base):
        lock_fd_identity = os.fstat(os.open(base / 'control.lock', os.O_RDONLY | os.O_NOFOLLOW))
        live_identity = [lock_fd_identity.st_dev, lock_fd_identity.st_ino]
        old = {n: record(base / n) for n in TARGETS}
        receipt = json.loads(data(old[RECEIPT]))
        require(sha(data(old[RECEIPT])) == current_pin, 'Old receipt pin changed')
        old_version = Path(receipt['stage']['version'])
        # Byte-level identity proof FIRST: modules must be identical to the
        # trusted stage. Any content difference here is drift, not re-id.
        verify_bundle(old_version, receipt['stage']['control_sha256'])
        stale_identity = receipt['lock_identity']
        require(isinstance(stale_identity, list) and len(stale_identity) == 2
                and all(type(v) is int for v in stale_identity), 'Malformed old lock identity')
        require(stale_identity[1] == live_identity[1],
                'Lock inode changed; this is not a benign volume re-id — stop')
        require(stale_identity[0] != live_identity[0],
                'Lock st_dev already matches; nothing to re-seal')
        # Verity.app and the stable launcher live on the same rotated volume; their
        # identity datums must be refreshed too (same re-id class, inodes must hold).
        app = Path.home() / 'Applications/Verity.app'
        launcher = base / 'production_launcher.py'
        app_st, launcher_st = app.lstat(), launcher.lstat()
        old_app_identity = receipt['stage']['app_identity']
        old_launcher_identity = receipt['stage']['launcher_identity']
        require(old_app_identity[1] == app_st.st_ino and old_app_identity[0] != app_st.st_dev,
                'Verity.app identity is not a benign volume re-id — stop')
        require(old_launcher_identity[1] == launcher_st.st_ino
                and old_launcher_identity[0] != launcher_st.st_dev,
                'Stable launcher identity is not a benign volume re-id — stop')
        require(receipt['stage']['control_sha256'] == json.loads(
            data(record(old_version / 'control-receipt.json'))), 'Stage receipt mismatch')
        env = json.loads(data(old[TRANSACTION]))
        require(env.get('schema_version') == 2 and env.get('control_refresh_sha256') == current_pin
                and env['transaction']['phase'] in ('verified', 'rolled_back'), 'Terminal transaction required')
        require(env['sha256'] == sha(json.dumps(env['transaction'], sort_keys=True,
                                              separators=(',', ':')).encode()), 'Transaction checksum mismatch')
        immutable = guards(base)
        new_version = base / 'control-refresh-versions' / version_name
        require(not new_version.exists() and not new_version.is_symlink(), 'Version already exists')
        # The new bundle carries the SAME module bytes as the trusted stage.
        raw_controls = {n: data(record(old_version / n)) for n in FILES}
        hashes = {n: sha(raw) for n, raw in raw_controls.items()}
        require(hashes == receipt['stage']['control_sha256'], 'Module bytes differ from trusted stage')
        source = output / 'controls'
        source.mkdir(mode=0o700)
        for n, raw in raw_controls.items():
            atomic(source / n, packed(raw))
        atomic(source / 'control-receipt.json', packed(encoded(hashes)))
        source.chmod(0o555)
        verify_bundle(source, hashes)
        stage = dict(receipt['stage'], version=str(new_version), control_sha256=hashes,
                     app_identity=[app_st.st_dev, app_st.st_ino],
                     launcher_identity=[launcher_st.st_dev, launcher_st.st_ino])
        fresh = dict(receipt, stage=stage, stage_sha256=sha(encoded(stage)),
                     lock_identity=live_identity)
        new_pin = sha(encoded(fresh))
        generated = wrappers(base, new_pin, new_version, source)
        require(set(generated) == set(WRAPPERS), 'Unexpected management wrapper set')
        new = {RECEIPT: packed(encoded(fresh), old[RECEIPT]['mode']),
               TRANSACTION: packed(encoded(dict(env, control_refresh_sha256=new_pin)), old[TRANSACTION]['mode'])}
        new.update({n: packed(generated[n].encode(), old[n]['mode']) for n in WRAPPERS})
        journal = dict(schema_version=1, kind='native-control-refresh', receipt=fresh,
                       stage_sha256=fresh['stage_sha256'], phase='committed', return_proof=None)
        new[JOURNAL] = packed(encoded(dict(payload=journal, sha256=sha(encoded(journal)))), old[JOURNAL]['mode'])
        plan = dict(schema_version=1, kind='post-native-management-upgrade', base=str(base),
                    old_pin=current_pin, new_pin=new_pin, old_version=str(old_version),
                    new_version=str(new_version), source_commit=commit, source_hashes=hashes,
                    reseal=dict(kind='lock-identity', from_identity=stale_identity,
                                to_identity=live_identity,
                                from_app_identity=old_app_identity,
                                from_launcher_identity=old_launcher_identity),
                    old=dict(old, receipt_app_inode=app_st.st_ino,
                             receipt_launcher_inode=launcher_st.st_ino),
                    new=new, guards=immutable)
        check_guards(immutable)
        require(all(record(base/n) == old[n] for n in TARGETS), 'Plan baseline changed')
        raw_plan = encoded(plan)
        require(len(raw_plan) <= MAX_PLAN_BYTES, 'Plan too large')
        validate_plan(plan)
        atomic(output / 'plan.json', packed(raw_plan, 0o400), max_bytes=MAX_PLAN_BYTES)
        return dict(status='planned_not_installed', plan=str(output/'plan.json'),
                    plan_sha256=sha(raw_plan), new_pin=new_pin, source_commit=commit,
                    reseal=dict(kind='lock-identity', from_identity=stale_identity,
                                to_identity=live_identity,
                                from_app_identity=old_app_identity,
                                from_launcher_identity=old_launcher_identity))


def build_plan(base, repo, commit, version_name, output, current_pin):
    base, repo = safe_dir(base), safe_dir(repo)
    require(re.fullmatch('[0-9a-f]{40}', commit) is not None, 'Exact source commit required')
    obj = source_git(repo, 'cat-file', '-t', commit)
    require(obj.returncode == 0 and obj.stdout.strip() == b'commit', 'Source object is not a genuine commit')
    require(re.fullmatch('[A-Za-z0-9_-]+', version_name) is not None, 'Invalid version name')
    require(re.fullmatch('[0-9a-f]{64}', current_pin) is not None, 'Exact old receipt pin required')
    # No exists()+overwrite: a fresh owned plan directory is mandatory.
    output = Path(output)
    safe_dir(output.parent)
    output.mkdir(mode=0o700)
    with locked(base):
        old = {n: record(base / n) for n in TARGETS}
        receipt = json.loads(data(old[RECEIPT]))
        require(sha(data(old[RECEIPT])) == current_pin, 'Old receipt pin changed')
        old_version = Path(receipt['stage']['version'])
        admit(base, current_pin, old_version)
        env = json.loads(data(old[TRANSACTION]))
        require(env.get('schema_version') == 2 and env.get('control_refresh_sha256') == current_pin
                and env['transaction']['phase'] in ('verified', 'rolled_back'), 'Terminal transaction required')
        require(env['sha256'] == sha(json.dumps(env['transaction'], sort_keys=True,
                                              separators=(',', ':')).encode()), 'Transaction checksum mismatch')
        immutable = guards(base)
        new_version = base / 'control-refresh-versions' / version_name
        require(not new_version.exists() and not new_version.is_symlink(), 'Version already exists')
        raw_controls = {n: git_file(repo, commit, n) for n in FILES}
        hashes = {n: sha(raw) for n, raw in raw_controls.items()}
        source = output / 'controls'
        source.mkdir(mode=0o700)
        for n, raw in raw_controls.items():
            atomic(source / n, packed(raw))
        atomic(source / 'control-receipt.json', packed(encoded(hashes)))
        source.chmod(0o555)
        verify_bundle(source, hashes)
        stage = dict(receipt['stage'], version=str(new_version), control_sha256=hashes)
        fresh = dict(receipt, stage=stage, stage_sha256=sha(encoded(stage)))
        new_pin = sha(encoded(fresh))
        generated = wrappers(base, new_pin, new_version, source)
        require(set(generated) == set(WRAPPERS), 'Unexpected management wrapper set')
        new = {RECEIPT: packed(encoded(fresh), old[RECEIPT]['mode']),
               TRANSACTION: packed(encoded(dict(env, control_refresh_sha256=new_pin)), old[TRANSACTION]['mode'])}
        new.update({n: packed(generated[n].encode(), old[n]['mode']) for n in WRAPPERS})
        journal = dict(schema_version=1, kind='native-control-refresh', receipt=fresh,
                       stage_sha256=fresh['stage_sha256'], phase='committed', return_proof=None)
        new[JOURNAL] = packed(encoded(dict(payload=journal, sha256=sha(encoded(journal)))), old[JOURNAL]['mode'])
        plan = dict(schema_version=1, kind='post-native-management-upgrade', base=str(base),
                    old_pin=current_pin, new_pin=new_pin, old_version=str(old_version),
                    new_version=str(new_version), source_commit=commit, source_hashes=hashes,
                    old=old, new=new, guards=immutable)
        check_guards(immutable)
        require(all(record(base/n) == old[n] for n in TARGETS), 'Plan baseline changed')
        raw_plan = encoded(plan)
        require(len(raw_plan) <= MAX_PLAN_BYTES, 'Plan too large')
        validate_plan(plan)
        atomic(output / 'plan.json', packed(raw_plan, 0o400), max_bytes=MAX_PLAN_BYTES)
        return dict(status='planned_not_installed', plan=str(output/'plan.json'),
                    plan_sha256=sha(raw_plan), new_pin=new_pin, source_commit=commit)


def read_plan(path, pin):
    path = Path(path)
    safe_dir(path.parent)
    raw = data(record(path, max_bytes=MAX_PLAN_BYTES), max_bytes=MAX_PLAN_BYTES)
    require(sha(raw) == pin, 'Explicit plan pin mismatch')
    plan = json.loads(raw)
    base = validate_plan(plan)
    return path, plan, base


def validate_plan(plan):
    require(isinstance(plan, dict) and plan.get('schema_version') == 1
            and plan.get('kind') == 'post-native-management-upgrade', 'Wrong plan schema')
    base = safe_dir(Path(plan['base']))
    require(set(plan['old']) == set(plan['new']) == set(TARGETS), 'Wrong publication targets')
    require(Path(plan['new_version']).parent == base/'control-refresh-versions'
            and re.fullmatch('[A-Za-z0-9_-]+', Path(plan['new_version']).name), 'Unsafe version path')
    for mapping in (plan['old'], plan['new'], plan['guards']):
        require(isinstance(mapping, dict), 'Invalid plan records')
        for rec in mapping.values():
            data(rec)
    return base


def verify_bundle(version, hashes):
    require(isinstance(hashes, dict) and set(hashes) == set(FILES)
            and all(isinstance(h, str) and re.fullmatch('[0-9a-f]{64}', h)
                    for h in hashes.values()), 'Invalid control hash authority')
    safe_dir(version)
    require(set(p.name for p in version.iterdir()) == set(FILES) | {'control-receipt.json'}, 'Control membership mismatch')
    require(stat.S_IMODE(version.stat().st_mode) == 0o555, 'Control directory mode mismatch')
    require(json.loads(data(record(version/'control-receipt.json'))) == hashes, 'Control hashes receipt mismatch')
    for n in (*FILES, 'control-receipt.json'):
        rec = record(version/n)
        require(rec['mode'] == 0o444, 'Control mode mismatch')
        if n in hashes:
            require(sha(data(rec)) == hashes[n], 'Staged control changed: ' + n)


def restore_known(base, plan):
    # Validate ALL bytes before restoring ANY. Unknown writes are never clobbered.
    check_guards(plan['guards'])
    observed = {n: record(base/n) for n in TARGETS}
    for n in TARGETS:
        require(observed[n] in (plan['old'][n], plan['new'][n]), 'Unknown publication drift: ' + n)
    for n in TARGETS:
        check_guards(plan['guards'])
        require(all(record(base/name) == rec for name, rec in observed.items()),
                'Concurrent recovery drift')
        atomic(base/n, plan['old'][n])
        observed[n] = plan['old'][n]
    require(all(record(base/n) == plan['old'][n] for n in TARGETS), 'Concurrent recovery drift')
    admit(base, plan['old_pin'], Path(plan['old_version']))
    check_guards(plan['guards'])


def admit_reseal_old(base, plan):
    """Old-state admission for re-seal apply, bypassing load()'s identity gate.

    load() refuses the drifted receipt by design — refusing the very drift this
    plan heals. Instead, admit the old state directly: receipt bytes pin-match,
    the trusted stage's bundle bytes verify, the installed wrapper set matches,
    and the lock identity equals exactly the plan's recorded stale identity
    (same inode, rotated st_dev). The NEW-state admission after publication
    still runs the real subprocess load(), which must pass with the healed
    identity.
    """
    require('reseal' in plan and plan['reseal']['kind'] == 'lock-identity',
            'admit_reseal_old requires a lock-identity re-seal plan')
    raw = data(record(base / RECEIPT))
    require(sha(raw) == plan['old_pin'], 'Management admission receipt pin mismatch')
    old_receipt = json.loads(raw)
    require(old_receipt['lock_identity'] == plan['reseal']['from_identity'],
            'Receipt identity differs from plan re-seal source')
    require(old_receipt['stage']['version'] == plan['old_version'],
            'Management admission version mismatch')
    old_version = Path(plan['old_version'])
    verify_bundle(old_version, old_receipt['stage']['control_sha256'])
    require(plan['source_hashes'] == old_receipt['stage']['control_sha256'],
            'Re-seal module bytes differ from trusted stage')
    lock_info = os.stat(base / 'control.lock')
    require([lock_info.st_dev, lock_info.st_ino] == plan['reseal']['to_identity'],
            'Live lock identity does not match the re-seal target')
    require(lock_info.st_ino == plan['reseal']['from_identity'][1],
            'Lock inode changed; not a benign re-id')
    # App + launcher inodes must equally have survived the volume re-id.
    app_st = (Path.home() / 'Applications/Verity.app').lstat()
    launcher_st = (base / 'production_launcher.py').lstat()
    require(app_st.st_ino == plan['old']['receipt_app_inode']
            and launcher_st.st_ino == plan['old']['receipt_launcher_inode'],
            'App/launcher inode changed; not a benign re-id')


def apply_plan(path, pin, *, recover=False, approval=False):
    require(approval is True, 'Explicit --approve required')
    path, plan, base = read_plan(path, pin)
    with locked(base):
        if recover:
            restore_known(base, plan)
            result = dict(status='restored_controls_no_restart', plan_sha256=pin)
        else:
            check_guards(plan['guards'])
            require(all(record(base/n) == plan['old'][n] for n in TARGETS), 'Installed baseline changed')
            if 'reseal' in plan:
                admit_reseal_old(base, plan)
            else:
                admit(base, plan['old_pin'], Path(plan['old_version']))
            source = path.parent/'controls'
            verify_bundle(source, plan['source_hashes'])
            target = Path(plan['new_version'])
            require(not target.exists() and not target.is_symlink(), 'Version exists; recover/replan, do not reuse')
            target.mkdir(mode=0o700)
            for n in (*FILES, 'control-receipt.json'):
                atomic(target/n, record(source/n))
            target.chmod(0o555)
            sync_dir(target.parent)
            verify_bundle(target, plan['source_hashes'])
            atomic(path.parent/'started.json', packed(encoded(dict(plan_sha256=pin)), 0o400))
            try:
                for n in TARGETS:
                    check_guards(plan['guards'])
                    require(record(base/n) == plan['old'][n], 'Concurrent target change: ' + n)
                    atomic(base/n, plan['new'][n])
                admit(base, plan['new_pin'], target)
                verify_bundle(target, plan['source_hashes'])
                check_guards(plan['guards'])
                require(all(record(base/n) == plan['new'][n] for n in TARGETS), 'Publication changed')
            except BaseException:
                restore_known(base, plan)
                raise
            result = dict(status='installed_controls_no_restart', plan_sha256=pin,
                          new_pin=plan['new_pin'], version=plan['new_version'])
        atomic(path.parent/'result.json', packed(encoded(result), 0o400))
        return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    s = p.add_subparsers(dest='command', required=True)
    b = s.add_parser('plan')
    for name in ('base', 'repo', 'output'):
        b.add_argument('--'+name, type=Path, required=True)
    for name in ('commit', 'version-name', 'current-pin'):
        b.add_argument('--'+name, required=True)
    b.add_argument('--reseal-lock-identity', action='store_true',
                   help='Recovery mode: publish the same trusted module bytes with the '
                        'live control.lock identity (st_dev rotation only; inode must match).')
    for command in ('apply', 'recover'):
        a = s.add_parser(command)
        a.add_argument('--plan', type=Path, required=True)
        a.add_argument('--plan-sha256', required=True)
        a.add_argument('--approve', action='store_true')
    args = p.parse_args()
    if args.command == 'plan':
        if args.reseal_lock_identity:
            result = build_reseal_plan(args.base, args.repo, args.commit, args.version_name,
                                       args.output, args.current_pin)
        else:
            result = build_plan(args.base, args.repo, args.commit, args.version_name,
                                args.output, args.current_pin)
    else:
        result = apply_plan(args.plan, args.plan_sha256, recover=args.command=='recover', approval=args.approve)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
