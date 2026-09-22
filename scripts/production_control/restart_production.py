#!/usr/bin/env python3
"""Fail-closed launchd restart/activation; no user-state or source-tree rollback."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import uuid

BASE = Path(__file__).resolve().parent
SERVICES = ('agent', 'webui')
ASSETS = ('boot.js', 'ui.js', 'panels.js', 'embed-host.js', 'i18n.js')


class ControlError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise ControlError(message)


def atomic_write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
    fd, name = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def save_json(path, data):
    atomic_write(path, (json.dumps(data, indent=2) + '\n').encode())


@contextmanager
def control_lock(base):
    with open(Path(base) / 'control.lock', 'a') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ControlError('Another restart/watchdog owns control.lock') from exc
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


def epoch(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    return parsed.replace(tzinfo=timezone.utc).timestamp() if parsed.tzinfo is None else parsed.timestamp()


def parse_job(text):
    """Parse launchctl print's top-level fields, not substring identity matches."""
    def field(name):
        matches = re.findall(r'^\t' + re.escape(name) + r' = (.+)$', text, re.M)
        require(len(matches) <= 1, 'Ambiguous launchd ' + name)
        return matches[0].strip().strip('"') if matches else None
    block = re.search(r'^\targuments = \{\n(.*?)^\t\}', text, re.M | re.S)
    require(block is not None, 'Cannot parse launchd arguments')
    args = []
    for line in block.group(1).splitlines():
        value = line.strip()
        value = re.sub(r'^\d+ = ', '', value)
        args.append(value.strip('"'))
    return {'argv': args, 'cwd': field('working directory'),
            'pid': int(field('pid')) if field('pid') else None}


class Host:
    def run(self, *args, check=True):
        result = subprocess.run(args, capture_output=True, text=True, timeout=30)
        if check and result.returncode:
            raise ControlError(f'{args[:2]}: {result.stderr.strip()}')
        return result

    def job(self, target):
        result = self.run('launchctl', 'print', target)
        return parse_job(result.stdout)

    def kickstart(self, target):
        self.run('launchctl', 'kickstart', '-k', target)

    def reload(self, target, plist):
        # A prior migration may have booted out successfully before bootstrap
        # failed. Only the documented missing-service code permits bootstrap
        # without bootout; permission/transport errors must fail closed.
        existing = self.run('launchctl', 'print', target, check=False)
        require(existing.returncode in (0, 113), 'Cannot inspect job for explicit reload')
        if existing.returncode == 0:
            self.run('launchctl', 'bootout', target)
        self.run('launchctl', 'bootstrap', target.rsplit('/', 1)[0], str(plist))

    def fetch(self, url):
        with urllib.request.urlopen(url, timeout=5) as response:
            require(response.status == 200 and response.geturl() == url, 'Unexpected HTTP response/redirect')
            return response.read()

    def listener(self, url):
        port = urllib.parse.urlsplit(url).port or 80
        result = self.run('lsof', '-nP', f'-iTCP:{port}', '-sTCP:LISTEN', '-t')
        return {int(p) for p in result.stdout.split()}

    def descendant(self, child, parent):
        seen = set()
        while child > 1 and child not in seen:
            if child == parent:
                return True
            seen.add(child)
            output = self.run('ps', '-p', str(child), '-o', 'ppid=').stdout.strip()
            if not output:
                return False
            child = int(output)
        return False


class Controller:
    def __init__(self, base=BASE, host=None, preflight_fn=None, clock=time.time,
                 monotonic=time.monotonic, sleep=time.sleep, owner=os.getppid,
                 timeout=90, stable_seconds=2):
        self.base = Path(base)
        self.manifest_path = self.base / 'production-release.json'
        self.host = host or Host()
        if preflight_fn is None:
            from production_launcher import preflight
            preflight_fn = preflight
        self.preflight_fn = preflight_fn
        self.clock, self.monotonic, self.sleep = clock, monotonic, sleep
        self.owner, self.timeout, self.stable_seconds = owner, timeout, stable_seconds
        self.domain = f'gui/{os.getuid()}'

    def load(self, path=None):
        data = json.loads(Path(path or self.manifest_path).read_text())
        require(data.get('schema_version') == 2, 'Manifest must have schema_version 2')
        require(set(data['services']) == set(SERVICES), 'Expected agent and webui')
        require(set(data['labels']) == set(SERVICES), 'Expected explicit labels')
        require(len(set(data['labels'].values())) == 2, 'Service labels must differ')
        return data

    def target(self, manifest, service):
        label = manifest['labels'][service]
        require(isinstance(label, str) and re.fullmatch(r'[A-Za-z0-9_.-]+', label), 'Invalid label')
        return self.domain + '/' + label

    def plist_path(self, manifest, service):
        return Path(manifest['services'][service].get('plist_path') or
                    Path.home() / 'Library/LaunchAgents' / (manifest['labels'][service] + '.plist'))

    def definitions(self, manifest, allow_cwd_change=False):
        result = {}
        for service in SERVICES:
            path = self.plist_path(manifest, service)
            data = plistlib.loads(path.read_bytes())
            argv = data.get('ProgramArguments', [])
            require(data.get('Label') == manifest['labels'][service], 'Plist label mismatch')
            require(len(argv) == 3 and Path(argv[0]).is_absolute() and
                    argv[1:] == [str(self.base / 'production_launcher.py'), service], 'Unexpected launcher argv')
            require(data.get('RunAtLoad') is True and data.get('KeepAlive') is True, 'Invalid lifecycle policy')
            if not allow_cwd_change:
                require(data.get('WorkingDirectory') == manifest['services'][service]['cwd'], 'Plist cwd mismatch')
            result[service] = data
        return result

    def loaded(self, manifest, definitions):
        jobs = {}
        for service in SERVICES:
            job = self.host.job(self.target(manifest, service))
            definition = definitions[service]
            require(job['argv'] == definition['ProgramArguments'] and
                    job['cwd'] == definition['WorkingDirectory'], f'{service}: cached launchd definition drift; use explicit --reload')
            jobs[service] = job
        return jobs

    def preflight(self, manifest):
        self.preflight_fn(manifest)

    def health(self, manifest, deep=False):
        url = manifest['health_url']
        if deep:
            url += ('&' if '?' in url else '?') + 'deep=1'
        data = json.loads(self.host.fetch(url))
        require(isinstance(data, dict) and data.get('status') == 'ok', 'Health JSON is not ok')
        return data

    def snapshot(self, manifest, definitions, since=None, previous=None):
        jobs = self.loaded(manifest, definitions)
        pids = {s: jobs[s]['pid'] for s in SERVICES}
        require(all(type(p) is int and p > 1 for p in pids.values()), 'Missing launchd PID')
        if previous is not None:
            require(all(pids[s] != previous[s].get('pid') for s in SERVICES), 'Launchd PID is not fresh')
        require(self.host.listener(manifest['health_url']) == {pids['webui']}, 'WebUI listener is not launchd PID')
        health = self.health(manifest)
        started = epoch(health['server_started_at'])
        require(started <= self.clock() + 5, 'Future WebUI start timestamp')
        if since is not None:
            require(started >= since - 1, 'Stale WebUI server_started_at')
        self.health(manifest, deep=True)
        origin = urllib.parse.urlsplit(manifest['health_url'])
        root = urllib.parse.urlunsplit((origin.scheme, origin.netloc, '', '', ''))
        repo = Path(manifest['services']['webui']['repo'])
        for name in ASSETS:
            expected = hashlib.sha256((repo / 'static' / name).read_bytes()).digest()
            actual = hashlib.sha256(self.host.fetch(root + '/static/' + name)).digest()
            require(actual == expected, 'Served asset mismatch: ' + name)
        state = json.loads((Path(manifest['state_dir']) / 'gateway_state.json').read_text())
        child = state.get('pid')
        require(type(child) is int and child > 1, 'Missing actual gateway child PID')
        require(self.host.descendant(child, pids['agent']), 'Gateway child is not owned by launchd job')
        require(state.get('gateway_state') == 'running', 'Gateway is not running')
        require(state.get('code_sha') == manifest['services']['agent']['commit'], 'Gateway code SHA mismatch')
        updated = epoch(state['updated_at'])
        require(self.clock() - 60 <= updated <= self.clock() + 5, 'Stale gateway state')
        if since is not None:
            require(updated >= since - 1, 'Gateway state predates restart')
        return {'pids': pids, 'gateway_child_pid': child, 'health': 'ok', 'deep_health': 'ok',
                'served_files_verified': list(ASSETS), 'messaging_delivery_tested': False}

    def wait_ready(self, manifest, definitions, since, previous):
        deadline = self.monotonic() + self.timeout
        stable = None
        stable_at = None
        error = 'No readiness sample'
        while self.monotonic() < deadline:
            try:
                proof = self.snapshot(manifest, definitions, since, previous)
                identity = (proof['pids'], proof['gateway_child_pid'])
                if identity != stable:
                    stable, stable_at = identity, self.monotonic()
                elif self.monotonic() - stable_at >= self.stable_seconds:
                    self.preflight(manifest)
                    return proof
            except Exception as exc:
                error = str(exc)
                stable = None
            self.sleep(1)
        raise ControlError('Readiness timeout: ' + error)

    def journal(self, operation_id, status, **fields):
        result = dict(operation_id=operation_id, status=status, timestamp=self.clock(), **fields)
        save_json(self.base / 'restart-result.json', result)
        with open(self.base / 'restart-journal.jsonl', 'a') as stream:
            stream.write(json.dumps(result) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        return result

    def restart(self, candidate=None, reload=False, yes=False, confirm=None):
        if yes:
            require(self.owner() == 1, '--yes requires a launchd-owned independent controller (ppid 1)')
        else:
            require(confirm is not None and confirm(), 'Explicit interactive confirmation required')
        operation_id = str(uuid.uuid4())
        with control_lock(self.base):
            return self._restart(operation_id, candidate, reload)

    def _restart(self, operation_id, candidate, reload):
        touched = False
        old_bytes = self.manifest_path.read_bytes()
        saved_plists = {}
        try:
            old = self.load()
            new = self.load(candidate) if candidate else old
            self.preflight(old)
            self.preflight(new)
            require(old['labels'] == new['labels'] and old['state_dir'] == new['state_dir'], 'Activation cannot migrate labels or user state')
            for service in SERVICES:
                require(self.plist_path(old, service) == self.plist_path(new, service), 'Activation cannot move plists')
            definitions = self.definitions(old)
            if reload:
                before = {s: self.host.job(self.target(old, s)) for s in SERVICES}
            else:
                before = self.loaded(old, definitions)
            new_definitions = {s: dict(definitions[s], WorkingDirectory=new['services'][s]['cwd']) for s in SERVICES}
            require(reload or new_definitions == definitions, 'Changed cwd requires explicit --reload')
            saved_plists = {self.plist_path(old, s): self.plist_path(old, s).read_bytes() for s in SERVICES}
            self.journal(operation_id, 'prepared')
            since = self.clock()
            touched = True  # Atomic replacement can succeed before a following fsync fails.
            if candidate:
                save_json(self.manifest_path, new)
            if reload:
                for service in SERVICES:
                    atomic_write(self.plist_path(new, service), plistlib.dumps(new_definitions[service]))
            for service in SERVICES:
                if reload:
                    self.host.reload(self.target(new, service), self.plist_path(new, service))
                else:
                    self.host.kickstart(self.target(new, service))
            proof = self.wait_ready(new, new_definitions, since, before)
            return self.journal(operation_id, 'verified', **proof)
        except Exception as exc:
            self.journal(operation_id, 'failed', error=str(exc))
            if not touched:
                raise
            try:
                atomic_write(self.manifest_path, old_bytes)
                for path, content in saved_plists.items():
                    atomic_write(path, content)
                self.preflight(old)
                since = self.clock()
                recovery_before = {}
                for service in SERVICES:
                    try:
                        recovery_before[service] = self.host.job(self.target(old, service))
                    except Exception:
                        recovery_before[service] = {'pid': None}
                for service in SERVICES:
                    if reload:
                        self.host.reload(self.target(old, service), self.plist_path(old, service))
                    else:
                        self.loaded(old, definitions)
                        self.host.kickstart(self.target(old, service))
                proof = self.wait_ready(old, definitions, since, recovery_before)
                return self.journal(operation_id, 'rolled_back', error=str(exc), recovery=proof)
            except Exception as recovery_error:
                return self.journal(operation_id, 'rollback_failed', error=str(exc), recovery_error=str(recovery_error))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, default=BASE)
    parser.add_argument('--restart', action='store_true')
    parser.add_argument('--yes', action='store_true')
    parser.add_argument('--activate', type=Path)
    parser.add_argument('--reload', action='store_true', help='Explicit launchd-definition migration')
    args = parser.parse_args(argv)
    if (args.yes or args.activate or args.reload) and not args.restart:
        parser.error('--yes/--activate/--reload require --restart')
    controller = Controller(args.base)
    if not args.restart:
        with control_lock(args.base):
            manifest = controller.load()
            controller.preflight(manifest)
            controller.loaded(manifest, controller.definitions(manifest))
        return {'status': 'checked', 'changed': False}
    return controller.restart(args.activate, args.reload, args.yes,
                              lambda: sys.stdin.isatty() and input('Type restart to interrupt both services: ') == 'restart')


if __name__ == '__main__':
    try:
        result = main()
        print(json.dumps(result))
        raise SystemExit(0 if result['status'] in ('verified', 'checked') else 1)
    except Exception as exc:
        print(f'STOPPED: {exc}', file=sys.stderr)
        raise SystemExit(1)
