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


def require(ok, message):
    if not ok:
        raise ValueError(message)


def encoded(obj):
    return (json.dumps(obj, indent=2, sort_keys=True) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def record(path) -> FileRecord:
    """No-follow, bounded read; reject inode/content metadata changing mid-read."""
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid()
                and not s.st_mode & 0o022 and s.st_size <= 64 * 1024 * 1024,
                'Unsafe input file: ' + str(path))
        with os.fdopen(fd, 'rb', closefd=False) as f:
            raw = f.read(64 * 1024 * 1024 + 1)
        t = os.fstat(fd)
        require((s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
                == (t.st_dev, t.st_ino, t.st_size, t.st_mtime_ns, t.st_ctime_ns)
                and path.lstat().st_ino == s.st_ino and len(raw) == s.st_size,
                'Input changed while read: ' + str(path))
        return FileRecord(data=base64.b64encode(raw).decode(), mode=stat.S_IMODE(s.st_mode), uid=s.st_uid)
    finally:
        os.close(fd)


def data(rec):
    require(isinstance(rec, dict) and set(rec) == {'data', 'mode', 'uid'}
            and rec['uid'] == os.getuid() and type(rec['mode']) is int
            and not rec['mode'] & 0o022, 'Invalid file record')
    return base64.b64decode(rec['data'], validate=True)


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


def atomic(path, rec):
    raw = data(rec)
    fd, tmp = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            os.fchmod(f.fileno(), rec['mode'])
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        sync_dir(path.parent)
        require(record(path) == rec, 'Publication readback failed')
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
        atomic(output / 'plan.json', packed(encoded(plan), 0o400))
        return dict(status='planned_not_installed', plan=str(output/'plan.json'),
                    plan_sha256=sha(encoded(plan)), new_pin=new_pin, source_commit=commit)


def read_plan(path, pin):
    path = Path(path)
    safe_dir(path.parent)
    raw = data(record(path))
    require(sha(raw) == pin, 'Explicit plan pin mismatch')
    plan = json.loads(raw)
    require(plan.get('schema_version') == 1 and plan.get('kind') == 'post-native-management-upgrade', 'Wrong plan schema')
    base = safe_dir(Path(plan['base']))
    require(set(plan['old']) == set(plan['new']) == set(TARGETS), 'Wrong publication targets')
    require(Path(plan['new_version']).parent == base/'control-refresh-versions'
            and re.fullmatch('[A-Za-z0-9_-]+', Path(plan['new_version']).name), 'Unsafe version path')
    for mapping in (plan['old'], plan['new']):
        for rec in mapping.values():
            data(rec)
    return path, plan, base


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
    for command in ('apply', 'recover'):
        a = s.add_parser(command)
        a.add_argument('--plan', type=Path, required=True)
        a.add_argument('--plan-sha256', required=True)
        a.add_argument('--approve', action='store_true')
    args = p.parse_args()
    if args.command == 'plan':
        result = build_plan(args.base, args.repo, args.commit, args.version_name, args.output, args.current_pin)
    else:
        result = apply_plan(args.plan, args.plan_sha256, recover=args.command=='recover', approval=args.approve)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
