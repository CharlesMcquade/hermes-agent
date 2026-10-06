#!/usr/bin/env python3
"""Fail-closed launchd restart/activation; no user-state or source-tree rollback."""
import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
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
def control_lock(base, expected_identity=None):
    path = Path(base) / 'control.lock'
    stream = (open(path, 'a') if expected_identity is None else
              os.fdopen(os.open(path, os.O_RDWR | os.O_NOFOLLOW), 'r+'))
    with stream:
        if expected_identity is not None:
            info = os.fstat(stream.fileno())
            require((info.st_dev, info.st_ino) == expected_identity, 'Control lock changed')
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
            self.run('launchctl', 'bootout', '--wait', target)
        self.run('launchctl', 'bootstrap', target.rsplit('/', 1)[0], str(plist))

    def fetch(self, url):
        with urllib.request.urlopen(url, timeout=5) as response:
            require(response.status == 200 and response.geturl() == url, 'Unexpected HTTP response/redirect')
            return response.read()

    def listener(self, url):
        port = urllib.parse.urlsplit(url).port or 80
        result = self.run('lsof', '-nP', f'-iTCP:{port}', '-sTCP:LISTEN', '-t')
        return {int(p) for p in result.stdout.split()}

    def process_identity(self, pid):
        from native_identity import process_identity
        return process_identity(pid)

    def verify_native_signature(self, pid, requirement):
        from native_identity import verify_signature
        return verify_signature(pid, requirement)

    def verify_native_bundle(self, bundle, requirement):
        return self.run('/usr/bin/codesign', '--verify', '--strict', '--deep',
                        '-R', '=' + requirement, bundle, check=False).returncode == 0

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
                 timeout=90, stable_seconds=2, control_refresh_sha256=None, pending_restart_sha256=None):
        self.pending_restart_sha256 = pending_restart_sha256
        self.base = Path(base)
        self.control_refresh_sha256 = control_refresh_sha256
        self.refresh_executor = Path(__file__).parent.parent.name == 'control-refresh-versions'
        require(self.refresh_executor == (control_refresh_sha256 is not None),
                'Refreshed executor requires an explicit control refresh pin; other executors exclude it')
        if control_refresh_sha256 is not None:
            require(isinstance(control_refresh_sha256, str)
                    and re.fullmatch(r'[0-9a-f]{64}', control_refresh_sha256),
                    'Explicit control refresh SHA-256 required')
        self.manifest_path = self.base / 'production-release.json'
        self.host = host or Host()
        if preflight_fn is None:
            from production_launcher import preflight
            preflight_fn = preflight
        self.preflight_fn = preflight_fn
        self.clock, self.monotonic, self.sleep = clock, monotonic, sleep
        self.owner, self.timeout, self.stable_seconds = owner, timeout, stable_seconds
        self.domain = f'gui/{os.getuid()}'

    @contextmanager
    def locked(self):
        identity = None
        if self.refresh_executor:
            identity = self.retained_file(self.base / 'control.lock')[1][0][:2]
        with control_lock(self.base, expected_identity=identity):
            yield

    def refresh_admission(self):
        """Caller holds control.lock; retained objects gain no authority after undo."""
        if not self.refresh_executor:
            return lambda: None
        try:
            from control_refresh import load
            _, _, unchanged = load(self.base, self.control_refresh_sha256, Path(__file__))
            self.read_transaction()
            return unchanged
        except (ValueError, OSError, KeyError, TypeError) as exc:
            raise ControlError('Control refresh admission refused: ' + str(exc)) from exc

    def load(self, path=None):
        return self.validate_manifest(json.loads(Path(path or self.manifest_path).read_text()))

    def validate_manifest(self, data):
        require(isinstance(data, dict) and data.get('schema_version') == 2, 'Manifest must have schema_version 2')
        require(set(data['services']) == set(SERVICES), 'Expected agent and webui')
        require(set(data['labels']) == set(SERVICES), 'Expected explicit labels')
        require(len(set(data['labels'].values())) == 2, 'Service labels must differ')
        if 'native_host' in data:
            from native_identity import contract
            contract(data)
        return data

    def target(self, manifest, service):
        label = manifest['labels'][service]
        require(isinstance(label, str) and re.fullmatch(r'[A-Za-z0-9_.-]+', label), 'Invalid label')
        return self.domain + '/' + label

    def plist_path(self, manifest, service):
        return Path(manifest['services'][service].get('plist_path') or
                    Path.home() / 'Library/LaunchAgents' / (manifest['labels'][service] + '.plist'))

    def definitions(self, manifest, allow_cwd_change=False, saved=None):
        if 'native_host' in manifest:
            from native_identity import validate_bundle
            validate_bundle(manifest, self.base, self.host)
        result = {}
        for service in SERVICES:
            path = self.plist_path(manifest, service)
            data = plistlib.loads(saved[service] if saved is not None else path.read_bytes())
            argv = data.get('ProgramArguments', [])
            require(data.get('Label') == manifest['labels'][service], 'Plist label mismatch')
            if 'native_host' in manifest:
                native = manifest['native_host']
                require(argv == [native['executable'], service], 'Unexpected native host argv')
                require(data.get('AssociatedBundleIdentifiers') == [native['bundle_id']],
                        'Native associated bundle mismatch')
            else:
                require(isinstance(argv, list) and len(argv) == 3 and
                        all(isinstance(v, str) and v and '\x00' not in v for v in argv) and
                        Path(argv[0]).is_absolute() and Path(argv[1]).is_absolute() and
                        argv[1:] == [str(manifest.get('launcher_path', self.base / 'production_launcher.py')), service], 'Unexpected launcher argv')
            require(Path(argv[0]).is_file() and os.access(argv[0], os.X_OK), 'Launcher Python is not executable')
            require(data.get('Program', argv[0]) == argv[0], 'Conflicting launchd Program')
            require(data.get('RunAtLoad') is True and data.get('KeepAlive') is True, 'Invalid lifecycle policy')
            # launchd has a stable anchor; the launcher chdirs into the selected release.
            anchor = Path(data.get('WorkingDirectory', ''))
            require(anchor.is_absolute() and anchor.is_dir(), 'Plist cwd is unavailable')
            result[service] = data
        return result

    def candidate_definitions(self, old, new, saved, reload):
        require(new.get('launcher_path', str(self.base / 'production_launcher.py')) ==
                old.get('launcher_path', str(self.base / 'production_launcher.py')),
                'Activation cannot change the stable launcher path')
        overrides = new.get('launchd_overrides', {})
        require(isinstance(overrides, dict) and set(overrides) <= set(SERVICES),
                'Unknown launchd override service')
        native = new.get('native_host')
        native_fields = {'AssociatedBundleIdentifiers', 'AbandonProcessGroup'}
        allowed = {'ProgramArguments', 'WorkingDirectory', 'EnvironmentVariables'}
        if native is not None:
            allowed |= native_fields
        proposed = {}
        for service in SERVICES:
            data = plistlib.loads(saved[service])
            override = overrides.get(service, {})
            require(isinstance(override, dict) and set(override) <= allowed,
                    'Unsupported launchd override field')
            if override:
                required = {'ProgramArguments', 'WorkingDirectory'}
                if native is not None:
                    required |= native_fields
                require(required <= set(override),
                        'Launchd override requires explicit argv and anchor and native policy when applicable')
                if native is not None:
                    require(override['ProgramArguments'] == [native['executable'], service],
                            'Unexpected native host argv')
                    require(type(override['AssociatedBundleIdentifiers']) is list and
                            override['AssociatedBundleIdentifiers'] == [native['bundle_id']],
                            'Native associated bundle mismatch')
                    require(override['AbandonProcessGroup'] is False,
                            'Native AbandonProcessGroup must be false')
            # A Program override wins over argv in launchd. Only the explicit
            # legacy-to-native migration may remove a previously matching one.
            source_argv = data.get('ProgramArguments', [])
            require('Program' not in data or
                    (source_argv and data['Program'] == source_argv[0]),
                    'Conflicting launchd Program')
            remove_program = (native is not None and 'native_host' not in old and
                              bool(override) and 'Program' in data)
            if 'EnvironmentVariables' in override:
                env = override['EnvironmentVariables']
                require(isinstance(env, dict) and all(
                    isinstance(k, str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', k)
                    and isinstance(v, str) and '\x00' not in v for k, v in env.items()),
                    'Invalid launchd environment')
            require('WorkingDirectory' not in override or
                    isinstance(override['WorkingDirectory'], str), 'Invalid launchd anchor')
            changed = remove_program or any(k not in data or data[k] != v or
                                            (k in native_fields and type(data[k]) is not type(v))
                                            for k, v in override.items())
            require(not changed or reload, 'Changed launchd overrides require explicit --reload')
            if remove_program:
                del data['Program']
            data.update(override)
            proposed[service] = plistlib.dumps(data)
        return self.definitions(new, saved=proposed)

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
        if 'native_host' in manifest:
            from native_identity import validate_bundle
            validate_bundle(manifest, self.base, self.host)
        self.preflight_fn(manifest)

    def listener_ownership(self, manifest, jobs, since=None):
        listeners = self.host.listener(manifest['health_url'])
        pid = jobs['webui']['pid']
        if 'native_host' not in manifest:
            require(listeners == {pid}, 'WebUI listener is not launchd PID')
            return None
        from native_identity import pair, unchanged
        require(len(listeners) == 1, 'Ambiguous native WebUI listener')
        identity = pair(manifest, 'webui', pid, next(iter(listeners)),
                        self.host, self.clock(), since)
        unchanged({'webui': identity}, self.host)
        require(self.host.job(self.target(manifest, 'webui')) == jobs['webui'],
                'Native launchd job changed during inspection')
        return identity

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
        web_identity = self.listener_ownership(manifest, jobs, since)
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
        process_identity = None
        if 'native_host' in manifest:
            from native_identity import pair
            process_identity = {'webui': web_identity,
                                'agent': pair(manifest, 'agent', pids['agent'], child,
                                              self.host, self.clock(), since)}
        else:
            require(self.host.descendant(child, pids['agent']), 'Gateway child is not owned by launchd job')
        require(state.get('gateway_state') == 'running', 'Gateway is not running')
        require(state.get('code_sha') == manifest['services']['agent']['commit'], 'Gateway code SHA mismatch')
        updated = epoch(state['updated_at'])
        require(updated <= self.clock() + 5, 'Future gateway state timestamp')
        # Runtime state updates on transitions, not idle heartbeats. Child ownership
        # proves liveness; only a post-restart check requires a fresh state write.
        if since is not None:
            require(updated >= since - 1, 'Gateway state predates restart')
        if process_identity is not None:
            from native_identity import unchanged
            unchanged(process_identity, self.host)
            require(self.loaded(manifest, definitions) == jobs, 'Native launchd PID changed during inspection')
            require(self.host.listener(manifest['health_url']) == {web_identity['child']['pid']},
                    'Native listener changed during inspection')
        proof = {'pids': pids, 'gateway_child_pid': child, 'health': 'ok', 'deep_health': 'ok',
                 'served_files_verified': list(ASSETS), 'messaging_delivery_tested': False}
        if process_identity is not None:
            proof['process_identity'] = process_identity
        return proof

    def wait_ready(self, manifest, definitions, since, previous):
        deadline = self.monotonic() + self.timeout
        stable = None
        stable_at = None
        error = 'No readiness sample'
        while self.monotonic() < deadline:
            try:
                proof = self.snapshot(manifest, definitions, since, previous)
                identity = (proof['pids'], proof['gateway_child_pid'], proof.get('process_identity'))
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

    def receipt(self, operation_id, status, **fields):
        # Informational receipts must not gate recovery; the transaction is the
        # durable authority. Prepared receipts deliberately use journal directly.
        try:
            return self.journal(operation_id, status, **fields)
        except OSError as exc:
            return dict(operation_id=operation_id, status=status,
                        timestamp=self.clock(), journal_error=str(exc), **fields)

    @property
    def transaction_path(self):
        return self.base / 'activation-transaction.json'

    @staticmethod
    def content_digest(manifest):
        """Stable digest of the service pair, including approved file inventories."""
        return hashlib.sha256(json.dumps(manifest['services'], sort_keys=True,
                                         separators=(',', ':')).encode()).hexdigest()

    def revocation_file(self):
        """Only a missing directory entry means no policy; reject links and drift."""
        path = self.base / 'revoked-releases.json'
        try:
            info = path.lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ControlError('Cannot inspect revocation policy') from exc
        require(stat.S_ISREG(info.st_mode), 'Unsafe revocation policy type')
        try:
            value = self.retained_file(path)
            after = path.lstat()
            fields = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            require(tuple(getattr(info, key) for key in fields) == value[1][0]
                    == tuple(getattr(after, key) for key in fields),
                    'Revocation policy changed while reading')
            return value
        except OSError as exc:
            raise ControlError('Cannot read revocation policy') from exc

    def check_revocation(self, manifest):
        # Absence means no revocations. A present policy must be completely valid;
        # misspelled keys must never silently disable an operator's revocation.
        value = self.revocation_file()
        if value is None:
            return
        policy = json.loads(value[0])
        require(isinstance(policy, dict) and set(policy) ==
                {'schema_version', 'release_ids', 'content_digests'} and
                type(policy['schema_version']) is int and policy['schema_version'] == 1,
                'Malformed revocation policy')
        for key in ('release_ids', 'content_digests'):
            require(isinstance(policy[key], list) and
                    all(isinstance(v, str) and v for v in policy[key]),
                    'Malformed revocation policy')
        require(all(re.fullmatch(r'[0-9a-f]{64}', v) for v in policy['content_digests']),
                'Malformed revocation digest')
        require(manifest.get('release_id') not in policy['release_ids'] and
                self.content_digest(manifest) not in policy['content_digests'],
                'Release is revoked')

    def save_transaction(self, txn, phase):
        txn['phase'] = phase
        payload = json.dumps(txn, sort_keys=True, separators=(',', ':')).encode()
        envelope = {'schema_version': 2 if self.refresh_executor else 1, 'transaction': txn,
                    'sha256': hashlib.sha256(payload).hexdigest()}
        if self.refresh_executor:
            envelope['control_refresh_sha256'] = self.control_refresh_sha256
        save_json(self.transaction_path, envelope)

    def read_transaction(self):
        if not self.transaction_path.exists():
            require(not self.refresh_executor, 'Missing control refresh transaction fence')
            return None
        envelope = json.loads(self.retained_file(self.transaction_path)[0] if self.refresh_executor
                              else self.transaction_path.read_text())
        require(isinstance(envelope, dict) and type(envelope.get('schema_version')) is int
                and envelope['schema_version'] == (2 if self.refresh_executor else 1),
                'Unsupported transaction schema')
        if self.refresh_executor:
            require(set(envelope) == {'schema_version', 'transaction', 'sha256', 'control_refresh_sha256'}
                    and envelope['control_refresh_sha256'] == self.control_refresh_sha256,
                    'Control refresh transaction fence mismatch')
        txn = envelope['transaction']
        payload = json.dumps(txn, sort_keys=True, separators=(',', ':')).encode()
        require(hashlib.sha256(payload).hexdigest() == envelope['sha256'],
                'Corrupt transaction backup')
        require(txn['phase'] in {'prepared', 'verified', 'rollback_started',
                                'rolled_back', 'rollback_failed'}, 'Invalid transaction phase')
        require(type(txn['reload']) is bool and isinstance(txn['operation_id'], str),
                'Invalid transaction identity')
        require(txn['authorization'] in {'verified-live-fallback', 'same-release-restart'},
                'Missing fallback authorization')
        if 'pending_restart_sha256' in txn:
            require(isinstance(txn['pending_restart_sha256'], str)
                    and re.fullmatch('[0-9a-f]{64}', txn['pending_restart_sha256']),
                    'Invalid pending transaction pin')
        return txn

    def recover_locked(self):
        """Caller holds control.lock. No inference from the current candidate.

        The backup is transaction-scoped authorization, not an expiring canary
        receipt or a global blessing. A consumed rollback is never attempted twice.
        """
        require(not os.path.lexists(self.base / 'pending-user-restart.json'),
                'Pending user restart requires pointer-only recovery, not process rollback')
        refresh_unchanged = self.refresh_admission()
        txn = self.read_transaction()
        require(txn is None or 'pending_restart_sha256' not in txn,
                'Pending user restart transaction requires pointer-only recovery')
        if txn is None or txn['phase'] in {'verified', 'rolled_back'}:
            return None
        if txn['phase'] == 'rollback_started':
            self.save_transaction(txn, 'rollback_failed')
        require(txn['phase'] != 'rollback_failed',
                'rollback_failed: manual reconciliation required')
        # Consume the sole attempt durably BEFORE any restoration or launchctl.
        refresh_unchanged()
        self.save_transaction(txn, 'rollback_started')
        try:
            old_bytes = base64.b64decode(txn['manifest'], validate=True)
            old = self.validate_manifest(json.loads(old_bytes))
            require(set(txn['plists']) == set(SERVICES), 'Incomplete plist backup')
            saved = {s: base64.b64decode(txn['plists'][s], validate=True) for s in SERVICES}
            definitions = self.definitions(old, saved=saved)
            self.check_revocation(old)
            self.preflight(old)
            if not txn['reload']:
                self.loaded(old, definitions)
            before = {}
            for service in SERVICES:
                try:
                    before[service] = self.host.job(self.target(old, service))
                except Exception:
                    before[service] = {'pid': None}
            refresh_unchanged()
            since = self.clock()
            atomic_write(self.manifest_path, old_bytes)
            for service in SERVICES:
                atomic_write(self.plist_path(old, service), saved[service])
            for service in SERVICES:
                if txn['reload']:
                    self.host.reload(self.target(old, service), self.plist_path(old, service))
                else:
                    self.host.kickstart(self.target(old, service))
            proof = self.wait_ready(old, definitions, since, before)
        except Exception as exc:
            self.save_transaction(txn, 'rollback_failed')
            return self.receipt(txn['operation_id'], 'rollback_failed', recovery_error=str(exc))
        self.save_transaction(txn, 'rolled_back')
        return self.receipt(txn['operation_id'], 'rolled_back', recovery=proof)

    @staticmethod
    def retained_file(path):
        """Read an owned regular file through canonical, non-writable ancestors."""
        path = Path(path)
        require(path.is_absolute() and path == path.resolve(), 'Unsafe retained path')
        ancestors = []
        for item in (path, *path.parents):
            info = item.lstat()
            if item != path:
                ancestors.append((info.st_dev, info.st_ino, info.st_uid, info.st_mode))
            require((stat.S_ISREG(info.st_mode) if item == path else stat.S_ISDIR(info.st_mode))
                    and info.st_uid in ({os.getuid()} if item == path else {0, os.getuid()})
                    and not info.st_mode & 0o7022, 'Unsafe retained owner/mode/type')
        before = path.stat()
        data = path.read_bytes()
        after = path.stat()
        def identity(info):
            return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_size,
                    info.st_mtime_ns, info.st_ctime_ns)

        require(identity(before) == identity(after), 'Retained file changed while reading')
        return data, (identity(after), tuple(ancestors))

    def upgraded_return(self, expected, root_pin, receipt, read):
        """Pinned one-hop deployment only; the root remains the baseline authority.

        Read retained provenance as data, never import installer/stager code. Keep
        filesystem observations for all prepublication edges under control.lock.
        """
        require(isinstance(expected, str) and re.fullmatch(r'[0-9a-f]{64}', expected),
                'Expected upgrade receipt SHA-256 required')
        def encoded(value):
            return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()

        def digest(value):
            return hashlib.sha256(value).hexdigest()

        def bounded(path):
            require(Path(path).lstat().st_size <= 4 * 1024 * 1024, 'Oversized upgrade provenance')
            return read(path)

        path = self.base / 'native-upgrade-receipt.json'
        raw = bounded(path)
        require(digest(raw) == expected and stat.S_IMODE(path.stat().st_mode) == 0o444,
                'Upgrade receipt pin or mode mismatch')
        envelope = json.loads(raw)
        require(set(envelope) == {'payload', 'sha256'}, 'Invalid upgrade envelope')
        payload = envelope['payload']
        require(digest(encoded(payload)) == envelope['sha256'], 'Corrupt upgrade receipt')
        require(set(payload) == {'schema_version', 'kind', 'phase', 'plan'}
                and type(payload['schema_version']) is int and payload['schema_version'] == 1
                and payload['kind'] == 'one-hop-native-upgrade' and payload['phase'] == 'committed',
                'Incomplete upgrade receipt')
        plan = payload['plan']
        require(set(plan) == {'root_sha256', 'original_stage', 'new_stage', 'original_report',
                             'new_report', 'original_stage_sha256', 'new_stage_sha256',
                             'v1_tree', 'v2_tree', 'v1_identity'}
                and plan['root_sha256'] == root_pin and plan['original_report'] == receipt['report'],
                'Upgrade root lineage mismatch')
        report, original = plan['new_report'], receipt['report']
        version = Path(report['final_control_version'])
        app = Path.home() / 'Applications/Verity.app'
        require(report['status'] == 'staged_not_activated' and report['activation_ready'] is False
                and report['final_base'] == str(self.base)
                and report['final_bundle'] == original['final_bundle'] == str(app)
                and version.parent == self.base / 'control-versions'
                and re.fullmatch(r'[A-Za-z0-9_-]+', version.name)
                and str(version) != original['final_control_version'], 'Invalid upgraded deployment')
        executor = Path(__file__)
        require(executor.is_absolute() and executor == executor.resolve()
                and executor == version / 'restart_production.py', 'Wrong upgraded executing controller')
        require(all(report[k] == original[k] for k in
                    ('selected_sha256', 'bootstrap_python', 'bootstrap_tmpdir')),
                'Upgrade baseline/bootstrap lineage mismatch')
        names = set(original['control_sha256'])
        require(set(report['control_sha256']) == names, 'Incomplete upgraded controls')
        directories = {}

        def directory(path):
            require(path.is_absolute() and path == path.resolve(), 'Unsafe upgrade directory')
            info = path.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                    and not info.st_mode & 0o7022, 'Unsafe upgrade directory metadata')
            value = (info.st_dev, info.st_ino, info.st_uid, info.st_mode,
                     info.st_mtime_ns, info.st_ctime_ns, tuple(sorted(p.name for p in path.iterdir())))
            if path in directories:
                require(directories[path] == value, 'Upgrade directory changed')
            else:
                directories[path] = value
            return info

        for controls in (Path(original['final_control_version']), version):
            require(stat.S_IMODE(directory(controls).st_mode) == 0o555
                    and set(p.name for p in controls.iterdir()) == names | {'control-receipt.json'},
                    'Upgraded control membership/mode drift')
        control_receipt = version / 'control-receipt.json'
        require(json.loads(read(control_receipt)) == report['control_sha256']
                and stat.S_IMODE(control_receipt.stat().st_mode) == 0o444,
                'Upgraded control receipt drift')
        for name in names:
            path = version / name
            data = read(path)
            require(stat.S_IMODE(path.stat().st_mode) == 0o444, 'Upgraded control mode drift')
            require(digest(data) == report['control_sha256'][name], 'Upgraded control drift')
        candidates = []
        for key, stage_report in (('original', original), ('new', report)):
            root = Path(plan[key + '_stage'])
            directory(root)
            raw = bounded(root / 'stage-report.json')
            require(digest(raw) == plan[key + '_stage_sha256'] and json.loads(raw) == stage_report,
                    'Upgrade retained stage lineage mismatch')
            raw = bounded(root / 'candidate-release.json')
            require(digest(raw) == stage_report['candidate_sha256'], 'Upgrade staged candidate drift')
            candidates.append(json.loads(raw))
        require(plan['original_stage'] != plan['new_stage']
                and candidates[0]['native_host']['requirement'] == candidates[1]['native_host']['requirement']
                and candidates[0]['services'] == candidates[1]['services'], 'Upgrade candidate lineage mismatch')
        rollback = dict(original['rollback_sha256'])
        replacements = {}
        before = f"sys.path.insert(0, {original['final_control_version']!r})\n".encode()
        after = f"sys.path.insert(0, {str(version)!r})\n".encode()
        for name, value in receipt['replacements'].items():
            data = base64.b64decode(value, validate=True)
            require(data.count(before) == 1, 'Invalid original wrapper version binding')
            replacements[name] = base64.b64encode(data.replace(before, after, 1)).decode()
            rollback['maintenance/' + name] = dict(sha256=digest(data), executable=False)
        require(report['rollback_sha256'] == rollback, 'Upgrade rollback lineage mismatch')

        def tree(root, expected_tree):
            actual = {}
            # Keys in the receipt never become filesystem paths or write targets.
            for path in (root, *root.rglob('*')):
                info = path.lstat()
                if stat.S_ISDIR(info.st_mode):
                    directory(path)
                    checksum = None
                else:
                    checksum = digest(read(path))
                actual[str(path.relative_to(root))] = dict(mode=stat.S_IMODE(info.st_mode),
                                                           uid=info.st_uid, sha256=checksum)
            require(actual == expected_tree, 'Upgraded app tree drift')
        retained = app.with_name('Verity.upgrade-v1.app')
        tree(retained, plan['v1_tree'])
        tree(app, plan['v2_tree'])
        require([retained.stat().st_dev, retained.stat().st_ino] == plan['v1_identity'],
                'Retained original app identity drift')

        def unchanged():
            require(not os.path.lexists(app.with_name('Verity.upgrade-v2.app')),
                    'Pending upgrade requires separate recovery')
            for path in tuple(directories):
                directory(path)
        unchanged()
        return report, replacements, unchanged

    def return_baseline(self, expected, controller_digest=None, upgrade_digest=None, refresh_digest=None):
        """Caller holds control.lock; resolve the independently retained install receipt.

        The externally approved file digest pins provenance; its internal checksum
        is corruption detection, not a signature or authorization by itself.
        """
        require(isinstance(expected, str) and re.fullmatch(r'[0-9a-f]{64}', expected),
                'Expected install receipt SHA-256 required')
        observed = {}

        def read(path):
            path = Path(path)
            value = self.retained_file(path)
            observed[path] = value
            return value[0]

        read(self.base / 'control.lock')
        raw = read(self.base / 'native-install-receipt.json')
        require(hashlib.sha256(raw).hexdigest() == expected, 'Install receipt digest mismatch')
        envelope = json.loads(raw)
        receipt = envelope['receipt']
        payload = (json.dumps(receipt, indent=2, sort_keys=True) + '\n').encode()
        require(type(envelope['schema_version']) is int and envelope['schema_version'] == 1
                and hashlib.sha256(payload).hexdigest() == envelope['sha256'], 'Corrupt install receipt')
        require(receipt['phase'] == 'installed' and receipt['base'] == str(self.base)
                and receipt['home'] == str(Path.home()), 'Foreign or incomplete install receipt')
        report = receipt['report']
        require(report['status'] == 'staged_not_activated' and report['activation_ready'] is False,
                'Invalid retained stage report')
        version = Path(report['final_control_version'])
        require(report['final_base'] == str(self.base)
                and version.parent == self.base / 'control-versions'
                and re.fullmatch(r'[A-Za-z0-9_-]+', version.name), 'Wrong installed control identity')
        if controller_digest is None and upgrade_digest is None and refresh_digest is None:
            require(Path(__file__).resolve().parent == version, 'Wrong installed control identity')
        names = {'restart_production.py', 'approved_restart_job.py', 'production_launcher.py',
                 'native_identity.py', 'watchdog.py'}
        require(set(report['control_sha256']) == names, 'Incomplete control provenance')
        require(json.loads(read(version / 'control-receipt.json')) == report['control_sha256']
                and stat.S_IMODE(version.stat().st_mode) == 0o555
                and stat.S_IMODE((version / 'control-receipt.json').stat().st_mode) == 0o444,
                'Control receipt or installed mode mismatch')
        for name in names:
            require(hashlib.sha256(read(version / name)).hexdigest() == report['control_sha256'][name]
                    and stat.S_IMODE((version / name).stat().st_mode) == 0o444,
                    'Installed control drift')
        executor_directory = None
        if controller_digest is not None:
            require(isinstance(controller_digest, str)
                    and re.fullmatch(r'[0-9a-f]{64}', controller_digest),
                    'Expected return controller SHA-256 required')
            executor = Path(__file__)
            executor_directory = executor.parent
            require(executor.is_absolute() and executor == executor.resolve()
                    and executor.name == 'restart_production.py'
                    and executor_directory.parent == self.base / 'return-control-versions'
                    and re.fullmatch(r'[A-Za-z0-9_-]+', executor_directory.name),
                    'Wrong return controller identity')
            descriptor_path = executor_directory / 'return-controller.json'
            descriptor_raw = read(descriptor_path)
            require(hashlib.sha256(descriptor_raw).hexdigest() == controller_digest,
                    'Return controller descriptor digest mismatch')
            descriptor = json.loads(descriptor_raw)
            require(set(descriptor) == {'schema_version', 'base', 'executor', 'installed_version',
                                        'install_receipt_sha256', 'control_sha256'}
                    and type(descriptor['schema_version']) is int and descriptor['schema_version'] == 1
                    and descriptor['base'] == str(self.base)
                    and descriptor['executor'] == str(executor)
                    and descriptor['installed_version'] == str(version)
                    and descriptor['install_receipt_sha256'] == expected
                    and set(descriptor['control_sha256']) == names,
                    'Foreign or incomplete return controller descriptor')
            require(stat.S_IMODE(executor_directory.stat().st_mode) == 0o555
                    and stat.S_IMODE(descriptor_path.stat().st_mode) == 0o444,
                    'Unsafe return controller mode')
            for name in names:
                path = executor_directory / name
                require(hashlib.sha256(read(path)).hexdigest() == descriptor['control_sha256'][name]
                        and stat.S_IMODE(path.stat().st_mode) == 0o444,
                        'Return controller drift')
        deployment, replacements, upgrade_unchanged = report, receipt['replacements'], None
        if upgrade_digest is not None:
            require(controller_digest is None, 'Upgrade and separate return executor pins are exclusive')
            deployment, replacements, upgrade_unchanged = self.upgraded_return(
                upgrade_digest, expected, receipt, read)
        if refresh_digest is not None:
            require(controller_digest is None and upgrade_digest is None
                    and refresh_digest == self.control_refresh_sha256 and self.refresh_executor,
                    'Control refresh return requires the exclusive current refresh pin')
            from control_refresh import load
            refresh, replacements, upgrade_unchanged = load(self.base, refresh_digest, Path(__file__), read=read)
            require(refresh['stage']['root_sha256'] == expected, 'Control refresh return root mismatch')
        wrappers = names - {'native_identity.py'}
        require(set(receipt['wrappers']) == set(receipt['replacements']) == wrappers,
                'Incomplete wrapper provenance')
        for name in wrappers:
            record = receipt['wrappers'][name]
            path = self.base / name
            require(read(path) == base64.b64decode(replacements[name], validate=True)
                    and type(record['uid']) is int and record['uid'] == os.getuid()
                    and type(record['mode']) is int
                    and stat.S_IMODE(path.stat().st_mode) == record['mode'], 'Installed wrapper drift')
        read(self.transaction_path)
        txn = self.read_transaction()
        require(txn is not None and txn['phase'] in {'verified', 'rolled_back'},
                'Return requires a terminal current transaction; use recovery separately')
        current = self.validate_manifest(json.loads(read(self.manifest_path)))
        require('native_host' in current and current['native_host']['bundle'] == deployment['final_bundle'],
                'Return requires the installed native selection')
        require(hashlib.sha256((json.dumps(current, indent=2, sort_keys=True) + '\n').encode()).hexdigest()
                == deployment['candidate_sha256'], 'Current selection differs from installed stage')
        records = receipt['baseline']
        record = records[str(self.manifest_path)]
        target = self.validate_manifest(json.loads(base64.b64decode(record['data'], validate=True)))
        require('native_host' not in target and 'launchd_overrides' not in target,
                'Retained baseline must be original legacy selection')
        require(target['labels'] == current['labels'] and target['state_dir'] == current['state_dir']
                and target.get('launcher_path') == current.get('launcher_path'),
                'Baseline labels/state/launcher mismatch')
        paths = [self.manifest_path] + [self.plist_path(target, s) for s in SERVICES]
        require(len(set(paths)) == 3 and set(records) == {str(p) for p in paths},
                'Incomplete or aliased baseline')
        for s in SERVICES:
            require(self.plist_path(target, s) == self.plist_path(current, s), 'Baseline plist path mismatch')
        exact = {}
        for path in paths:
            record = records[str(path)]
            require(set(record) == {'data', 'mode', 'uid'} and type(record['mode']) is int
                    and 0 <= record['mode'] <= 0o777 and not record['mode'] & 0o022
                    and type(record['uid']) is int and record['uid'] == os.getuid(),
                    'Malformed baseline metadata')
            read(path)
            require(stat.S_IMODE(path.stat().st_mode) == record['mode'], 'Baseline mode drift')
            exact[path] = base64.b64decode(record['data'], validate=True)
        require(hashlib.sha256(exact[self.manifest_path]).hexdigest() == report['selected_sha256'],
                'Retained manifest stage mismatch')
        # Stage rollback copies are deliberately mode 0600, independently of
        # the original modes retained in the installer snapshot records.
        rollback = {s + '.plist': {'sha256': hashlib.sha256(exact[self.plist_path(target, s)]).hexdigest(),
                                   'executable': False}
                    for s in SERVICES}
        for name in wrappers:
            record = receipt['wrappers'][name]
            rollback['maintenance/' + name] = dict(
                sha256=hashlib.sha256(base64.b64decode(record['data'], validate=True)).hexdigest(),
                executable=False)
        require(rollback == report['rollback_sha256'], 'Retained rollback stage mismatch')
        policy = self.revocation_file()

        def unchanged(prepared=None):
            if upgrade_unchanged is not None:
                upgrade_unchanged()
            if executor_directory is not None:
                require({p.name for p in executor_directory.iterdir()} == names | {'return-controller.json'},
                        'Unexpected return controller members')
            require(self.revocation_file() == policy, 'Revocation policy changed')
            for path, value in observed.items():
                if path == self.transaction_path and prepared is not None:
                    self.retained_file(path)
                    require(self.read_transaction() == prepared, 'Prepared return transaction changed')
                else:
                    require(self.retained_file(path) == value, 'Return input changed: ' + str(path))
            for name in ('restart-result.json', 'restart-journal.jsonl'):
                path = self.base / name
                require(not path.is_symlink(), 'Unsafe receipt output')
                if path.exists():
                    self.retained_file(path)

        unchanged()
        return target, exact, unchanged, {Path(p): r['mode'] for p, r in records.items()}

    def restart(self, candidate=None, reload=False, yes=False, confirm=None, return_baseline=None,
                return_controller_sha256=None, return_upgrade_sha256=None, return_control_refresh_sha256=None):
        require(return_control_refresh_sha256 is None or (return_baseline is not None and reload
                and candidate is None and return_controller_sha256 is None and return_upgrade_sha256 is None
                and return_control_refresh_sha256 == self.control_refresh_sha256),
                'Control refresh return pin requires exclusive --return-baseline --reload and matching refresh pin')
        require(not self.refresh_executor or return_baseline is None
                or return_control_refresh_sha256 is not None, 'Refreshed return requires explicit return refresh pin')
        require(return_upgrade_sha256 is None or (return_baseline is not None and reload
                and candidate is None and return_controller_sha256 is None),
                'Upgrade pin requires exclusive --return-baseline and --reload')
        require(return_controller_sha256 is None or (return_baseline is not None and reload and candidate is None),
                'Return controller pin requires --return-baseline and --reload')
        if yes:
            require(self.owner() == 1, '--yes requires a launchd-owned independent controller (ppid 1)')
        else:
            require(confirm is not None and confirm(), 'Explicit interactive confirmation required')
        operation_id = str(uuid.uuid4())
        if return_baseline is not None:
            require(candidate is None and reload, 'Return requires --reload and excludes --activate')
            lock_identity = self.retained_file(self.base / 'control.lock')
        with self.locked():
            self.refresh_admission()
            pending_txn = self.read_transaction()
            require(not os.path.lexists(self.base / 'pending-user-restart.json')
                    and (pending_txn is None or 'pending_restart_sha256' not in pending_txn),
                    'Pending user restart excludes generic restart/return; use supported UI controls')
            if return_baseline is not None:
                require(self.retained_file(self.base / 'control.lock') == lock_identity, 'Control lock changed')
                exact = self.return_baseline(return_baseline, return_controller_sha256, return_upgrade_sha256,
                                             return_control_refresh_sha256)
                return self._restart(operation_id, None, True, exact, return_baseline,
                                     return_controller_sha256, return_upgrade_sha256,
                                     return_control_refresh_sha256)
            recovery = self.recover_locked()
            if recovery is not None:
                return recovery  # Recovery never activates the supplied candidate.
            return self._restart(operation_id, candidate, reload)

    def _restart(self, operation_id, candidate, reload, exact=None, baseline_digest=None, controller_digest=None,
                 upgrade_digest=None, refresh_digest=None):
        refresh_unchanged = self.refresh_admission()
        touched = False
        old_bytes = self.manifest_path.read_bytes()
        saved_plists = {}
        try:
            old = self.load()
            new = exact[0] if exact else (self.load(candidate) if candidate else old)
            self.check_revocation(old)
            self.check_revocation(new)
            self.preflight(old)
            self.preflight(new)
            require(old['labels'] == new['labels'] and old['state_dir'] == new['state_dir'], 'Activation cannot migrate labels or user state')
            for service in SERVICES:
                require(self.plist_path(old, service) == self.plist_path(new, service), 'Activation cannot move plists')
            saved_plists = {s: self.plist_path(old, s).read_bytes() for s in SERVICES}
            definitions = self.definitions(old, saved=saved_plists)
            if reload:
                before = {s: self.host.job(self.target(old, s)) for s in SERVICES}
            else:
                before = self.loaded(old, definitions)
            if candidate or exact:
                self.snapshot(old, definitions)  # Only a proven live pair can be a candidate's fallback.
            new_definitions = (self.definitions(new, saved={s: exact[1][self.plist_path(new, s)] for s in SERVICES})
                               if exact else self.candidate_definitions(old, new, saved_plists, reload)
                               if candidate else definitions)
            txn = {'operation_id': operation_id, 'reload': reload,
                   'authorization': 'verified-live-fallback' if candidate or exact else 'same-release-restart',
                   'manifest': base64.b64encode(old_bytes).decode('ascii'),
                   'plists': {s: base64.b64encode(b).decode('ascii') for s, b in saved_plists.items()}}
            if exact:
                exact[2]()
                txn.update(operation='return-retained-baseline', baseline_sha256=baseline_digest)
                if refresh_digest is not None:
                    txn['control_refresh_sha256'] = refresh_digest
                if upgrade_digest is not None:
                    txn['upgrade_sha256'] = upgrade_digest
                if controller_digest is not None:
                    txn['return_controller_sha256'] = controller_digest
            refresh_unchanged()
            self.journal(operation_id, 'prepared')
            refresh_unchanged()
            if exact:
                exact[2]()
            self.save_transaction(txn, 'prepared')
            refresh_unchanged()
            if exact:
                exact[2](txn)
            since = self.clock()
            touched = True  # Atomic replacement can succeed before a following fsync fails.
            if exact:
                atomic_write(self.manifest_path, exact[1][self.manifest_path])
            elif candidate:
                save_json(self.manifest_path, new)
            if reload:
                for service in SERVICES:
                    path = self.plist_path(new, service)
                    atomic_write(path, exact[1][path] if exact else plistlib.dumps(new_definitions[service]))
            for service in SERVICES:
                if reload:
                    self.host.reload(self.target(new, service), self.plist_path(new, service))
                else:
                    self.host.kickstart(self.target(new, service))
            proof = self.wait_ready(new, new_definitions, since, before)
            if exact:
                for path, data in exact[1].items():
                    require(self.retained_file(path)[0] == data
                            and stat.S_IMODE(path.stat().st_mode) == exact[3][path],
                            'Exact return readback mismatch')
            self.save_transaction(txn, 'verified')
        except Exception as exc:
            if exact and not touched:
                raise  # A rejected input must not write through an unsafe receipt path.
            self.receipt(operation_id, 'failed', error=str(exc))
            if not touched:
                raise
            recovery = self.recover_locked()
            if recovery is None:  # Final fsync may fail after the terminal rename.
                raise
            return recovery
        return self.receipt(operation_id, 'verified', **proof)


class UniquePin(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest, None) is not None:
            parser.error(str(option_string) + ' cannot be supplied more than once')
        if not isinstance(values, str) or not re.fullmatch('[0-9a-f]{64}', values):
            parser.error(str(option_string) + ' requires lowercase SHA-256')
        setattr(namespace, self.dest, values)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, default=BASE)
    parser.add_argument('--restart', action='store_true')
    parser.add_argument('--yes', action='store_true')
    target = parser.add_mutually_exclusive_group()
    target.add_argument('--activate', type=Path)
    target.add_argument('--return-baseline', metavar='INSTALL_RECEIPT_SHA256',
                        help='Explicit exact legacy return using the retained installed receipt')
    parser.add_argument('--reload', action='store_true', help='Explicit launchd-definition migration')
    parser.add_argument('--return-controller-sha256', metavar='DESCRIPTOR_SHA256',
                        help='Explicit separately retained return-controller descriptor pin')
    parser.add_argument('--return-upgrade-sha256', metavar='UPGRADE_RECEIPT_SHA256',
                        help='Explicit committed one-hop upgrade deployment pin')
    parser.add_argument('--control-refresh-sha256', action=UniquePin)
    parser.add_argument('--return-control-refresh-sha256', action=UniquePin)
    args = parser.parse_args(argv)
    if args.return_control_refresh_sha256 is not None:
        if not (args.return_baseline is not None and args.restart and args.reload
                and args.return_controller_sha256 is None and args.return_upgrade_sha256 is None
                and args.control_refresh_sha256 in (None, args.return_control_refresh_sha256)):
            parser.error('--return-control-refresh-sha256 requires exclusive return route and matching pin')
        args.control_refresh_sha256 = args.return_control_refresh_sha256
    if args.return_upgrade_sha256 is not None and not (args.return_baseline is not None
            and args.restart and args.reload and args.return_controller_sha256 is None):
        parser.error('--return-upgrade-sha256 requires exclusive --return-baseline --restart --reload')
    if args.return_controller_sha256 is not None and not (args.return_baseline is not None and args.restart and args.reload):
        parser.error('--return-controller-sha256 requires --return-baseline --restart --reload')
    if args.return_baseline is not None and not args.reload:
        parser.error('--return-baseline requires --reload')
    if (args.yes or args.activate or args.reload or args.return_baseline is not None) and not args.restart:
        parser.error('--yes/--activate/--reload require --restart')
    controller = Controller(args.base, control_refresh_sha256=args.control_refresh_sha256)
    if not args.restart:
        with controller.locked():
            controller.refresh_admission()
            manifest = controller.load()
            controller.preflight(manifest)
            controller.loaded(manifest, controller.definitions(manifest))
        return {'status': 'checked', 'changed': False}
    return controller.restart(args.activate, args.reload, args.yes,
                              lambda: sys.stdin.isatty() and input('Type restart to interrupt both services: ') == 'restart',
                              return_baseline=args.return_baseline, return_controller_sha256=args.return_controller_sha256,
                              return_upgrade_sha256=args.return_upgrade_sha256,
                              return_control_refresh_sha256=args.return_control_refresh_sha256)


if __name__ == '__main__':
    try:
        result = main()
        print(json.dumps(result))
        raise SystemExit(0 if result['status'] in ('verified', 'checked') else 1)
    except Exception as exc:
        print(f'STOPPED: {exc}', file=sys.stderr)
        raise SystemExit(1)
