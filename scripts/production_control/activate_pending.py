#!/usr/bin/env python3
"""Ordered activation of a SELECTED pending user-restart, with proofs.

Human authorization is the explicit --pin (the pending receipt SHA-256), which
only exists after a separately approved select operation. Like
select_for_user_restart.py, the installed six-module control bundle is prehashed
against the reviewed refresh receipt and those exact bytes are executed — the
development tree never acts on production state.

The script performs the ordered handoff the pending protocol expects: Restart
WebUI, prove the candidate identity + listener ownership + health, then Restart
Gateway, then wait for natural scheduled watchdog publication of a verified
result matching the exact pending receipt, bounded by --settle-timeout. Never
force watchdog ticks or call a private observer to shorten settlement.

On any failure: STOP and report. No automatic rollback here — recovery is the
watchdog's deadline expiry (selection auto-restores) plus the retained baseline
return route, both of which stay available.
"""
import argparse
import hashlib
import json
import os
import stat
import sys
import time
import types
from contextlib import contextmanager
from pathlib import Path

MODULES = ('production_launcher', 'restart_production', 'native_identity',
           'control_refresh', 'watchdog', 'approved_restart_job')
ORDER = ('webui', 'agent')  # ordered handoff: WebUI first, Gateway second


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def retained(path):
    path = Path(path)
    require(path.is_absolute() and path == path.resolve(), 'Noncanonical or symlink input')
    for ancestor in (path, *path.parents):
        st = ancestor.lstat()
        require(st.st_uid in {0, os.getuid()} and not st.st_mode & 0o7022, 'Unsafe input owner/mode')
        require(stat.S_ISREG(st.st_mode) if ancestor == path else stat.S_ISDIR(st.st_mode),
                'Unsafe input type')
    before = path.stat()
    require(before.st_size <= 64 * 1024 * 1024, 'Oversized input')
    raw = path.read_bytes()
    require(before == path.stat(), 'Input changed during read')
    return raw


def prehash_bundle(base, controls, pin):
    """No installed Python executes before the complete pinned set is retained."""
    receipt_path = base / 'native-control-refresh-receipt.json'
    receipt = retained(receipt_path)
    require(digest(receipt) == pin, 'Control refresh receipt pin mismatch')
    stage = json.loads(receipt)['stage']
    require(stage['base'] == str(base) and stage['version'] == str(controls),
            'Wrong installed control bundle')
    hashes = stage['control_sha256']
    require(set(hashes) == {n + '.py' for n in MODULES}, 'Incomplete six-module authority')
    require(set(p.name for p in controls.iterdir()) == set(hashes) | {'control-receipt.json'},
            'Foreign control bundle membership')
    require(json.loads(retained(controls / 'control-receipt.json')) == hashes,
            'Control bundle receipt mismatch')
    bytes_ = {}
    for name, checksum in hashes.items():
        raw = retained(controls / name)
        require(digest(raw) == checksum, 'Unpinned control module: ' + name)
        bytes_[name] = raw
    return bytes_


@contextmanager
def installed_modules(controls, bytes_):
    require(not any(n in sys.modules for n in MODULES),
            'Refuse preloaded control modules; use a fresh isolated interpreter')
    loaded = {}
    try:
        for name in MODULES:
            module = types.ModuleType(name)
            module.__file__ = str(controls / (name + '.py'))
            sys.modules[name] = module
            exec(compile(bytes_[name + '.py'], module.__file__, 'exec'), module.__dict__)
            loaded[name] = module
        yield loaded['restart_production'], loaded['watchdog']
    finally:
        for name in MODULES:
            sys.modules.pop(name, None)


def find_child_pid(controller, manifest, service, host_pid):
    """The launchd job pid is the native host; find its child running candidate bytes."""
    release_dir = f"/.hermes/releases/{manifest['release_id']}/"
    marker = 'server.py' if service == 'webui' else 'gateway run'
    try:
        output = controller.run('ps', '-axo', f'pid=,command=').stdout
    except Exception:
        return None
    for line in output.splitlines():
        line = line.strip()
        if release_dir not in line or marker not in line:
            continue
        try:
            pid = int(line.split(None, 1)[0])
        except ValueError:
            continue
        if controller.descendant(pid, host_pid):
            return pid
    return None


def wait_service_new(controller, manifest, service, old_pid, since, deadline):
    """Resumable: 'new' means candidate child bytes under the launchd host."""
    defs = controller.definitions(manifest)
    while time.time() < deadline:
        jobs = controller.loaded(manifest, defs)
        host_pid = jobs[service]['pid']
        pid = find_child_pid(controller, manifest, service, host_pid)
        if pid:
            if service == 'webui':
                controller.listener_ownership(manifest, jobs, since=None)
                controller.health(manifest)
            return pid
        time.sleep(4)
    raise RuntimeError(f'{service}: candidate identity not observed before deadline')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, default=Path.home() / '.hermes/maintenance')
    parser.add_argument('--controls', type=Path, required=True)
    parser.add_argument('--pin', required=True, help='Pending receipt SHA-256 (the authorization)')
    parser.add_argument('--control-refresh-sha256', required=True)
    parser.add_argument('--service-timeout', type=float, default=240.0)
    parser.add_argument('--settle-timeout', type=float, default=420.0)
    args = parser.parse_args()
    base = Path(args.base)
    controls = Path(args.controls)

    bytes_ = prehash_bundle(base, controls, args.control_refresh_sha256)
    report = {'started_at': time.time()}  # type: dict
    with installed_modules(controls, bytes_) as (rp, pending):
        c = rp.Controller(base, control_refresh_sha256=args.control_refresh_sha256)
        with c.locked():
            c.refresh_admission()
            receipt, old, new, _ = pending.load(c, args.pin)
            require(time.time() < receipt['deadline'],
                    'Pending receipt expired; selection will auto-restore')
            current = c.retained_file(c.manifest_path)
            require(current[0] == pending.decode(receipt['new']),
                    'Selector is not the candidate; nothing to activate')
            c.check_revocation(new)
            c.preflight(new)
            defs = c.definitions(new)
            before = {s: c.loaded(new, defs)[s]['pid'] for s in ORDER}
            report['before_pids'] = before
            report['deadline_in_min'] = round((receipt['deadline'] - time.time()) / 60, 1)

            for service in ORDER:
                current_jobs = c.loaded(new, c.definitions(new))
                if find_child_pid(c, new, service, current_jobs[service]['pid']):
                    report[f'{service}_new_pid'] = current_jobs[service]['pid']
                    report[f'{service}_skipped_kick'] = True
                    print(json.dumps({service: 'already-new'}), flush=True)
                    continue
                kicked = time.time()
                c.host.kickstart(c.target(new, service))
                new_pid = wait_service_new(c, new, service, before[service], kicked,
                                           kicked + args.service_timeout)
                report[f'{service}_new_pid'] = new_pid
                print(json.dumps({service: 'new-verified', 'pid': new_pid}), flush=True)

        # Observe natural scheduled publication; never accelerate watchdog settlement.
        settle_deadline = time.time() + args.settle_timeout
        last = None
        while time.time() < settle_deadline:
            time.sleep(12)
            result_path = base / pending.RESULT
            if result_path.exists():
                last = json.loads(result_path.read_text())
                if last.get('status') == 'verified' and last.get('receipt_sha256') == args.pin:
                    report['settlement'] = last
                    report['status'] = 'verified'
                    print(json.dumps(report))
                    return 0
    report['status'] = 'settle_timeout'
    report['last_result'] = last
    print(json.dumps(report))
    return 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f'STOPPED: {exc}', file=sys.stderr)
        raise SystemExit(2)
