"""Ordered process activation for an already-admitted, pinned pending operation.

The independent runner owns approval, executable admission and its own lock.
This engine never installs controls, changes plists, forces watchdog observations,
or deletes pending authority. Exceptions are caller-visible; the runner decides
whether its explicit fallback authorization permits rollback_pending().
"""
import hashlib
import json
import math
from pathlib import Path
import time
import urllib.parse


ORDER = ('webui', 'agent')


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def _stable_gateway_state(c, manifest):
    """Read gateway-maintained state through its rewrite races, bounded.

    The gateway rewrites gateway_state.json outside the controller lock; a
    stat-read-stability read can lose that race (either stability check's
    message). Content checks still gate everything downstream — only the
    transient rewrite race is absorbed.
    """
    path = Path(manifest['state_dir']) / 'gateway_state.json'
    transient_msgs = {'Input changed during read', 'Retained file changed while reading'}
    last = None
    for attempt in range(10):
        try:
            return json.loads(c.retained_file(path)[0])
        except Exception as exc:  # installed ControlError is not a RuntimeError
            transient = (str(exc) in transient_msgs
                         or 'owns control.lock' in str(exc)
                         or isinstance(exc, BlockingIOError))
            if not transient:
                raise
            last = exc
        time.sleep(0.25 * (attempt + 1))
    raise RuntimeError('Gateway state did not stabilize: ' + str(last))


def _guard(c, pending, pin, selected, *, expiring=False):
    refresh = c.refresh_admission()
    r, old, new, unchanged = pending.load(c, pin)
    current = c.retained_file(c.manifest_path)
    require(current[0] == pending.decode(r[selected]), 'Pending selector mismatch')
    if expiring:
        require(c.clock() < r['deadline'], 'Pending receipt expired')
    for manifest in ((old, new) if selected == 'new' else (old,)):
        c.check_revocation(manifest)
        c.preflight(manifest)
    refresh()
    unchanged()
    require(c.retained_file(c.manifest_path) == current, 'Selector changed during admission')
    return r, old, new


def _identity(c, manifest, service):
    from native_identity import pair, unchanged
    jobs = c.loaded(manifest, c.definitions(manifest))
    if service == 'webui':
        listeners = c.host.listener(manifest['health_url'])
        require(len(listeners) == 1, 'Ambiguous WebUI listener')
        child = next(iter(listeners))
    else:
        state = _stable_gateway_state(c, manifest)
        child = state.get('pid')
    identity = pair(manifest, service, jobs[service]['pid'], child, c.host, c.clock())
    unchanged({service: identity}, c.host)
    require(c.loaded(manifest, c.definitions(manifest)) == jobs, 'Jobs changed during inspection')
    return identity


def _ready(c, manifest, service):
    from native_identity import unchanged
    from restart_production import ASSETS
    identity = _identity(c, manifest, service)
    if service == 'webui':
        c.health(manifest)
        c.health(manifest, deep=True)
        origin = urllib.parse.urlsplit(manifest['health_url'])
        root = urllib.parse.urlunsplit((origin.scheme, origin.netloc, '', '', ''))
        repo = Path(manifest['services']['webui']['repo'])
        for name in ASSETS:
            expected = hashlib.sha256((repo / 'static' / name).read_bytes()).digest()
            actual = hashlib.sha256(c.host.fetch(root + '/static/' + name)).digest()
            require(actual == expected, 'Served asset mismatch: ' + name)
    else:
        state = _stable_gateway_state(c, manifest)
        require(state.get('pid') == identity['child']['pid']
                and state.get('gateway_state') == 'running'
                and state.get('code_sha') == manifest['services']['agent']['commit'],
                'Gateway readiness mismatch')
    unchanged({service: identity}, c.host)
    require(_identity(c, manifest, service) == identity, 'Service changed during readiness')
    return identity


def _wait_service(c, pending, pin, selected, service, timeout):
    deadline = c.monotonic() + timeout
    error = 'No readiness sample'
    while c.monotonic() < deadline:
        with c.locked():
            _, old, new = _guard(c, pending, pin, selected, expiring=selected == 'new')
            target = new if selected == 'new' else old
            try:
                return _ready(c, target, service)
            except Exception as exc:
                # No signals here. Missing jobs, stale gateway state and socket
                # handover are transient only within this bounded read-only wait.
                error = str(exc)
        c.sleep(1)
    raise RuntimeError(service + ' readiness timeout: ' + error)


def _ordered(c, pending, pin, checkpoint, selected, timeout):
    from native_identity import unchanged as identity_unchanged
    from restart_production import ControlError
    report = {}
    for service in ORDER:
        with c.locked():
            r, old, new = _guard(c, pending, pin, selected, expiring=selected == 'new')
            target = new if selected == 'new' else old
            # Positively identify BOTH current owners before any signal. In
            # particular, unreadable is not absent. Down-service recovery is
            # intentionally refused: this engine has no bootstrap authority.
            _, _, identities = pending.effective_pair(c, old, new)
            if service == 'agent':
                _ready(c, target, 'webui')
            try:
                exact = _identity(c, target, service)
            except ControlError:
                exact = None  # effective_pair already proved a permitted owner
            if exact is None:
                checkpoint('before_kick', service=service, selected=selected,
                           operation_id=r['operation_id'], identity=identities[service])
                # Checkpoint persistence can take time; admission and owners must
                # still match at the actual signal boundary.
                _guard(c, pending, pin, selected, expiring=selected == 'new')
                identity_unchanged(identities, c.host)
                require(pending.effective_pair(c, old, new)[2] == identities,
                        'Owners changed before kick')
                if service == 'agent':
                    _ready(c, target, 'webui')
                identity_unchanged(identities, c.host)
                c.host.kickstart(c.target(target, service))
            report[service] = {'skipped_kick': exact is not None}
        report[service]['process_identity'] = _wait_service(
            c, pending, pin, selected, service, timeout)
    return report


def _settle(c, pending, pin, selected, timeout, stable_seconds, *, progress=None):
    started = c.monotonic()
    deadline = started + timeout
    stable, stable_at, error = None, None, 'No stable sample'
    last_observation, last_report = None, started
    while c.monotonic() < deadline:
        if selected == 'new':
            # This is ONLY a wake-up hint, not authority. The scheduled writer
            # needs control.lock: repeatedly doing two release preflights under
            # that lock before looking for its result starves its natural ticks.
            # Stay entirely outside the lock until a matching terminal appears;
            # then re-read and validate EVERYTHING under the lock below.
            try:
                hint = json.loads(c.retained_file(c.base / pending.RESULT)[0])
                ready = (isinstance(hint, dict) and hint.get('status') == 'verified'
                         and hint.get('receipt_sha256') == pin
                         and hint.get('selected') == 'new')
                observation = 'terminal_available' if ready else 'not_verified'
                error = 'Waiting for exact scheduled verification'
            except FileNotFoundError:
                ready, observation, error = False, 'missing', 'Scheduled result missing'
            except Exception as exc:
                ready, observation, error = False, 'unreadable', str(exc)
            if progress is not None and (observation != last_observation
                                        or c.monotonic() - last_report >= 30):
                progress('awaiting_watchdog', observation=observation,
                         elapsed_seconds=round(c.monotonic() - started, 1))
                last_observation, last_report = observation, c.monotonic()
            if not ready:
                stable, stable_at = None, None
                c.sleep(1)
                continue
        with c.locked():
            r, old, new = _guard(c, pending, pin, selected)
            target = new if selected == 'new' else old
            try:
                proof = c.snapshot(target, c.definitions(target))
                identity = proof['process_identity']
                if stable != identity:
                    stable, stable_at = identity, c.monotonic()
                if c.monotonic() - stable_at >= stable_seconds:
                    if selected == 'old':
                        return {'status': 'rolled_back', 'proof': proof}
                    result = json.loads(c.retained_file(c.base / pending.RESULT)[0])
                    require(result.get('status') == 'verified'
                            and result.get('operation_id') == r['operation_id']
                            and result.get('receipt_sha256') == pin
                            and result.get('selected') == 'new'
                            and result.get('candidate_identity') == identity
                            and result.get('process_identity') == identity
                            and result.get('proof', {}).get('process_identity') == identity,
                            'Scheduled pending result does not verify current pair')
                    completed = result.get('completed_at')
                    require(type(completed) in (int, float) and math.isfinite(completed)
                            and r['created_at'] <= completed < r['deadline']
                            and completed <= c.clock() + 5, 'Invalid scheduled completion time')
                    return {'status': 'verified', 'proof': proof, 'settlement': result}
            except Exception as exc:
                error = str(exc)
                stable, stable_at = None, None
        c.sleep(1)  # release control.lock so the scheduled watchdog can publish
    raise RuntimeError('Pending settlement timeout: ' + error)


def run_activation(c, pending, pin, checkpoint, *, service_timeout=180,
                   settle_timeout=900, stable_seconds=10):
    """Activate WebUI then Gateway; return only after natural watchdog proof."""
    for value in (service_timeout, settle_timeout, stable_seconds):
        require(type(value) in (int, float) and math.isfinite(value) and value > 0,
                'Timeouts and stable_seconds must be finite and positive')
    services = _ordered(c, pending, pin, checkpoint, 'new', service_timeout)
    result = _settle(c, pending, pin, 'new', settle_timeout, stable_seconds,
                     progress=checkpoint)
    return dict(result, services=services, receipt_sha256=pin)


def rollback_pending(c, pending, pin, checkpoint):
    """Explicit authorized process rollback, retaining every receipt and fence.

    Unknown or down owners fail closed, including before selector restoration.
    The caller must not claim rollback succeeded merely because selection moved.
    """
    with c.locked():
        refresh = c.refresh_admission()
        r, old, new, unchanged = pending.load(c, pin)
        c.check_revocation(old)
        c.preflight(old)
        c.definitions(old)
        identities = pending.effective_pair(c, old, new)[2]
        checkpoint('before_restore_selection', operation_id=r['operation_id'])
        from native_identity import unchanged as identity_unchanged
        identity_unchanged(identities, c.host)
        c.check_revocation(old)
        c.preflight(old)
        pending.restore_selection(c, r, refresh, unchanged)
    services = _ordered(c, pending, pin, checkpoint, 'old', 180)
    result = _settle(c, pending, pin, 'old', 900, 10)
    return dict(result, services=services, receipt_sha256=pin)
