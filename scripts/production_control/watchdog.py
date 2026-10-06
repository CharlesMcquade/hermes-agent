#!/usr/bin/env python3
"""One conservative WebUI watchdog tick. Schedule externally; never installs jobs."""
import argparse
import base64
import copy
import hashlib
import math
import os
import re
import uuid
import json
from pathlib import Path
import sys

from restart_production import (BASE, SERVICES, Controller, ControlError, UniquePin,
                                atomic_write, require, save_json)


def tick(controller, grace=90, cooldown=300, max_backoff=3600):
    """Only shallow liveness failures justify a restart; deep failures are degraded."""
    path = controller.base / 'watchdog-state.json'
    try:
        with controller.locked():
            return _tick(controller, path, grace, cooldown, max_backoff)
    except ControlError as exc:
        if 'owns control.lock' in str(exc):
            return {'status': 'busy', 'changed': False}
        raise


def _tick(c, path, grace, cooldown, max_backoff):
    state = json.loads(path.read_text()) if path.exists() else {}
    now = c.clock()
    def finish(status, **fields):
        state.update(status=status, timestamp=now, **fields)
        save_json(path, state)
        return state
    try:
        refresh_unchanged = c.refresh_admission()
        pending = None
        txn = c.read_transaction()
        fenced_pin = txn.get('pending_restart_sha256') if txn else None
        if c.pending_restart_sha256 is not None or fenced_pin is not None or os.path.lexists(c.base / RECEIPT):
            if c.pending_restart_sha256 is None:
                c.pending_restart_sha256 = fenced_pin
            pending = observe(c, c.pending_restart_sha256)
            state['pending'] = pending
            require('running' in pending, 'Pending identity unavailable; no process authority')
            _, old, new, _ = load(c, c.pending_restart_sha256)
            manifest, _, _ = effective_pair(c, old, new)
        else:
            recovery = c.recover_locked()
            if recovery is not None:
                return finish(recovery['status'], recovery=recovery, failures=0)
            manifest = c.load()
            c.check_revocation(manifest)
        definitions = c.definitions(manifest)
        jobs = c.loaded(manifest, definitions)
    except Exception as exc:
        return finish('blocked', error=str(exc), failures=0)
    pid = jobs['webui']['pid']
    if pid != state.get('pid'):
        state.update(pid=pid, first_seen=now, failures=0)
    if pid and now - state.get('first_seen', now) < grace:
        return finish('grace', failures=0)
    try:
        if not pid:
            raise ControlError('No WebUI PID')
        c.listener_ownership(manifest, jobs)
        c.health(manifest)
    except Exception as exc:
        state['failures'] = min(2, state.get('failures', 0) + 1)
        state['error'] = str(exc)
    else:
        state['failures'] = 0
        try:
            c.snapshot(manifest, definitions)
        except Exception as exc:
            return finish('degraded', error=str(exc))
        return finish('healthy', attempts=0, error=None)
    if state['failures'] < 2:
        return finish('suspect')
    if now < state.get('next_attempt', 0):
        return finish('cooldown')
    try:
        refresh_unchanged()
    except Exception as exc:
        return finish('blocked', error=str(exc))
    # Persist the attempt BEFORE a side effect: a killed watchdog cannot hot-loop.
    attempts = min(8, state.get('attempts', 0) + 1)
    finish('checking', attempts=attempts,
           next_attempt=now + min(max_backoff, cooldown * 2 ** (attempts - 1)))
    try:
        if pending is None:
            c.preflight(manifest)
        c.loaded(manifest, definitions)
        refresh_unchanged()
        if pending is not None:
            manifest = pending_repair_guard(c, pending)
        c.host.kickstart(c.target(manifest, 'webui'))
    except Exception as exc:
        return finish('blocked', error=str(exc))
    # This records an attempt, never unearned readiness proof; next ticks verify.
    return finish('restart_requested', failures=0, first_seen=now)

RECEIPT = 'pending-user-restart.json'
RESULT = 'pending-user-restart-result.json'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def record(c, path):
    raw, identity = c.retained_file(path)
    return dict(data=base64.b64encode(raw).decode(), sha256=digest(raw),
                identity=json.loads(json.dumps(identity)))


def decode(value):
    raw = base64.b64decode(value['data'], validate=True)
    require(digest(raw) == value['sha256'], 'Pending backup digest mismatch')
    return raw


def compatible(c, old, new):
    # No app, launcher, state, supervisor or plist migrations in this protocol.
    for key in ('native_host', 'labels', 'state_dir', 'health_url', 'launcher_path'):
        require(old.get(key) == new.get(key), 'Pending transition cannot migrate ' + key)
    require('native_host' in old, 'Pending transition requires native process identities')
    for role in SERVICES:
        require(c.plist_path(old, role) == c.plist_path(new, role), 'Pending plist path changed')
    require(c.definitions(old) == c.definitions(new), 'Pending supervisor definitions differ')
    saved = {s: c.plist_path(old, s).read_bytes() for s in SERVICES}
    c.candidate_definitions(old, new, saved, reload=False)


def prepare(c, candidate, *, expected_old_sha256, expected_new_sha256, timeout=3600):
    """Create a receipt only. Caller separately approves its returned digest to select."""
    require(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 86400,
            'Pending timeout must be positive and at most one day')
    with c.locked():
        unchanged = c.refresh_admission()
        txn = c.read_transaction()
        if txn is None:
            raise ControlError('Pending preparation requires a terminal activation transaction')
        require(txn['phase'] in {'verified', 'rolled_back'} and 'pending_restart_sha256' not in txn,
                'Pending preparation requires an unfenced terminal activation transaction')
        require(not os.path.lexists(c.base / RECEIPT), 'Pending receipt already exists')
        old_record = record(c, c.manifest_path)
        new_record = record(c, candidate)
        require(old_record['sha256'] == expected_old_sha256
                and new_record['sha256'] == expected_new_sha256, 'Pending selection pin mismatch')
        old = c.validate_manifest(json.loads(decode(old_record)))
        new = c.validate_manifest(json.loads(decode(new_record)))
        require(decode(old_record) != decode(new_record), 'Pending selection must change')
        compatible(c, old, new)
        for manifest in (old, new):
            c.check_revocation(manifest)
            c.preflight(manifest)
        plists = {s: record(c, c.plist_path(old, s)) for s in SERVICES}
        proof = c.snapshot(old, c.definitions(old))
        require('process_identity' in proof, 'Missing native fallback identity')
        receipt = dict(schema_version=1, kind='pending-user-restart', operation_id=str(uuid.uuid4()),
                       base=str(c.base), control_refresh_sha256=c.control_refresh_sha256,
                       created_at=c.clock(), deadline=c.clock() + timeout,
                       old=old_record, new=new_record, plists=plists, original=proof,
                       original_transaction=record(c, c.transaction_path),
                       lock_identity=[])
        info = (c.base / 'control.lock').stat()
        receipt['lock_identity'] = [info.st_dev, info.st_ino]
        unchanged()
        require(record(c, c.manifest_path) == old_record, 'Selection changed during preparation')
        for s in SERVICES:
            require(record(c, c.plist_path(old, s)) == plists[s], 'Plist changed during preparation')
        require(c.snapshot(old, c.definitions(old)) == proof, 'Fallback changed during preparation')
        require(record(c, c.transaction_path) == receipt['original_transaction'], 'Transaction changed')
        save_json(c.base / RECEIPT, receipt)
        raw = c.retained_file(c.base / RECEIPT)[0]
        require(json.loads(raw) == receipt, 'Pending receipt readback mismatch')
        txn['pending_restart_sha256'] = digest(raw)
        c.save_transaction(txn, txn['phase'])
        require(c.read_transaction() == txn, 'Pending transaction fence readback failed')
        return dict(status='prepared_not_selected', changed=True, selection_changed=False,
                    process_action='none', receipt_sha256=digest(raw))


def load(c, pin, *, allow_unfenced=False):
    require(isinstance(pin, str) and re.fullmatch('[0-9a-f]{64}', pin),
            'Explicit pending receipt SHA-256 required')
    retained = c.retained_file(c.base / RECEIPT)
    require(digest(retained[0]) == pin, 'Pending receipt pin mismatch')
    r = json.loads(retained[0])
    require(type(r.get('schema_version')) is int and r['schema_version'] == 1
            and r.get('kind') == 'pending-user-restart' and r['base'] == str(c.base)
            and r['control_refresh_sha256'] == c.control_refresh_sha256,
            'Foreign pending authority')
    require(type(r['deadline']) in (int, float) and math.isfinite(r['deadline'])
            and 0 < r['deadline'] - r['created_at'] <= 86400, 'Invalid pending deadline')
    info = (c.base / 'control.lock').stat()
    require(r['lock_identity'] == [info.st_dev, info.st_ino], 'Pending lock changed')
    original_txn = json.loads(decode(r['original_transaction']))['transaction']
    expected_txn = dict(original_txn, pending_restart_sha256=pin)
    fenced = c.read_transaction() == expected_txn
    require(fenced or (allow_unfenced and record(c, c.transaction_path) == r['original_transaction']),
            'Pending transaction fence drift')
    old, new = [c.validate_manifest(json.loads(decode(r[k]))) for k in ('old', 'new')]
    compatible(c, old, new)
    for s in SERVICES:
        require(record(c, c.plist_path(old, s)) == r['plists'][s], 'Pending plist drift')
    transaction = c.retained_file(c.transaction_path)
    def unchanged():
        require(c.retained_file(c.transaction_path) == transaction, 'Pending transaction changed')
        info = (c.base / 'control.lock').stat()
        require(r['lock_identity'] == [info.st_dev, info.st_ino], 'Pending lock changed')
        require(c.retained_file(c.base / RECEIPT) == retained, 'Pending receipt changed')
        for s in SERVICES:
            require(record(c, c.plist_path(old, s)) == r['plists'][s], 'Pending plist drift')
    return r, old, new, unchanged


def select(c, pin):
    """Guarded pointer-only publication. Does not call recovery or restart."""
    with c.locked():
        refresh = c.refresh_admission()
        r, old, new, unchanged = load(c, pin, allow_unfenced=True)
        txn = c.read_transaction()
        if txn is None:
            raise ControlError('Missing pending transaction')
        require(txn['phase'] in {'verified', 'rolled_back'}, 'Unsettled activation')
        require(c.clock() < r['deadline'], 'Pending receipt expired')
        for m in (old, new):
            c.check_revocation(m)
            c.preflight(m)
        if c.retained_file(c.manifest_path)[0] == decode(r['new']):
            require(txn.get('pending_restart_sha256') == pin, 'Unfenced selected candidate')
            return dict(status='already_selected', changed=False, receipt_sha256=pin)
        require(c.snapshot(old, c.definitions(old)) == r['original'], 'Original fallback identity changed')
        refresh()
        unchanged()
        require(record(c, c.manifest_path) == r['old'], 'Pending selector CAS failed')
        if txn.get('pending_restart_sha256') != pin:
            # Explicit retry after a prepare crash may finish its exact old fence.
            require(record(c, c.transaction_path) == r['original_transaction'], 'Transaction changed')
            txn['pending_restart_sha256'] = pin
            c.save_transaction(txn, txn['phase'])
            require(c.read_transaction() == txn, 'Pending fence readback failed')
        atomic_write(c.manifest_path, decode(r['new']))
        require(c.retained_file(c.manifest_path)[0] == decode(r['new']), 'Selection readback failed')
        return dict(status='selected_awaiting_user_restart', changed=True, receipt_sha256=pin)


def restore_selection(c, r, refresh, unchanged):
    """CAS bytes under control.lock; no process authority is implied by this undo."""
    current = c.retained_file(c.manifest_path)
    require(current[0] in (decode(r['old']), decode(r['new'])), 'Rollback selector CAS failed')
    refresh()
    unchanged()
    require(c.retained_file(c.manifest_path) == current, 'Rollback selector changed')
    if current[0] != decode(r['old']):
        atomic_write(c.manifest_path, decode(r['old']))
    require(c.retained_file(c.manifest_path)[0] == decode(r['old']), 'Rollback readback failed')


def effective_pair(c, old, new):
    """Classify runtime identity independently of HTTP/deep-health availability."""
    from native_identity import pair, unchanged
    jobs = c.loaded(old, c.definitions(old))
    listeners = c.host.listener(old['health_url'])
    require(len(listeners) == 1, 'Ambiguous pending WebUI listener')
    gateway = json.loads((Path(old['state_dir']) / 'gateway_state.json').read_text())
    children = dict(webui=next(iter(listeners)), agent=gateway['pid'])
    running, identities = {}, {}
    for role in SERVICES:
        for name, manifest in (('old', old), ('new', new)):
            try:
                identity = pair(manifest, role, jobs[role]['pid'], children[role], c.host, c.clock())
            except ControlError:
                continue
            running[role], identities[role] = name, identity
            break
        require(role in running, 'Unknown pending ' + role + ' identity')
    unchanged(identities, c.host)
    require(c.loaded(old, c.definitions(old)) == jobs, 'Pending jobs changed during observation')
    effective = copy.deepcopy(old)
    sources = dict(old=old, new=new)
    effective['services'] = {s: sources[running[s]]['services'][s] for s in SERVICES}
    return effective, running, identities


def observe(c, pin, *, rollback=False):
    """Caller owns control.lock. Mixed pairs are observations, not selected releases."""
    refresh = c.refresh_admission()
    r, old, new, unchanged = load(c, pin)
    txn = c.read_transaction()
    require(txn is None or txn['phase'] in {'verified', 'rolled_back'}, 'Unsettled activation')
    current = c.retained_file(c.manifest_path)
    require(current[0] in (decode(r['old']), decode(r['new'])), 'Pending selection drift')
    c.check_revocation(old)
    prior = {}
    if os.path.lexists(c.base / RESULT):
        prior = json.loads(c.retained_file(c.base / RESULT)[0])
        require(prior.get('receipt_sha256') == pin, 'Foreign pending result')
    completed = prior.get('completed_at')
    if completed is not None:
        require(type(completed) in (int, float) and math.isfinite(completed)
                and r['created_at'] <= completed < r['deadline'] and completed <= c.clock() + 5,
                'Invalid pending completion timestamp')
    expired = c.clock() >= r['deadline'] and completed is None
    revoked = False
    try:
        c.check_revocation(new)
    except ControlError:
        revoked = True
    if rollback or expired or revoked:
        c.preflight(old)
        restore_selection(c, r, refresh, unchanged)
        current = c.retained_file(c.manifest_path)
    result = dict(operation_id=r['operation_id'], receipt_sha256=pin, timestamp=c.clock(),
                  selected='old' if current[0] == decode(r['old']) else 'new',
                  process_action='none', messaging_delivery_tested=False)
    if completed is not None:
        result['completed_at'] = completed
    try:
        effective, running, identities = effective_pair(c, old, new)
        result.update(running=running, process_identity=identities)
        proof = c.snapshot(effective, c.definitions(effective))
        result['proof'] = proof
        all_old = all(v == 'old' for v in running.values())
        result['status'] = 'awaiting_user_restart' if all_old else 'transition'
        # Runtime-equivalent roles may classify as old. Full new snapshot is the
        # actual completion proof; it must be stable across separate observations.
        try:
            new_proof = c.snapshot(new, c.definitions(new))
        except Exception:
            new_proof = None
        if new_proof is not None and result['selected'] == 'new':
            c.preflight(new)
            stable_since = (prior.get('stable_since', c.clock())
                            if prior.get('candidate_identity') == new_proof['process_identity']
                            else c.clock())
            result.update(status='candidate_observed', stable_since=stable_since,
                          candidate_identity=new_proof['process_identity'])
            if c.clock() - stable_since >= c.stable_seconds and (completed is not None or c.clock() < r['deadline']):
                result.update(status='verified', completed_at=completed or c.clock())
        if result['selected'] == 'old':
            result['status'] = 'old_observed' if all_old else 'rollback_user_restart_required'
    except Exception as exc:
        result.update(status='transition_unhealthy', error=str(exc))
    if rollback or expired or revoked:
        result.update(selection_rollback=True, reason='requested' if rollback else 'expired' if expired else 'revoked')
    refresh()
    unchanged()
    require(c.retained_file(c.manifest_path) == current, 'Selection changed during observation')
    save_json(c.base / RESULT, result)
    return result


def pending_repair_guard(c, observation):
    """Liveness repair may not become an implicit candidate cutover or rollback."""
    from native_identity import unchanged as identities_unchanged
    refresh = c.refresh_admission()
    r, old, new, unchanged = load(c, c.pending_restart_sha256)
    effective, running, identities = effective_pair(c, old, new)
    require(identities == observation['process_identity'], 'Pending owner changed before repair')
    selected = c.retained_file(c.manifest_path)[0]
    if running['webui'] == 'old':
        # Repair old against old selection, never kill it to activate a candidate.
        c.check_revocation(old)
        c.preflight(old)
        restore_selection(c, r, refresh, unchanged)
    else:
        require(selected == decode(r['new']), 'Rollback grants no candidate process authority')
        c.check_revocation(new)
        c.preflight(new)
    refresh()
    unchanged()
    identities_unchanged(identities, c.host)
    require(c.retained_file(c.manifest_path)[0] == decode(r[running['webui']]),
            'Pending selector changed before liveness repair')
    return effective


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, default=BASE)
    parser.add_argument('--control-refresh-sha256', action=UniquePin)
    parser.add_argument('--pending-restart-sha256', action=UniquePin)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument('--prepare-pending', type=Path, metavar='CANDIDATE')
    actions.add_argument('--select-pending', action='store_true')
    actions.add_argument('--rollback-selection', action='store_true')
    parser.add_argument('--expected-old-sha256', action=UniquePin)
    parser.add_argument('--expected-new-sha256', action=UniquePin)
    parser.add_argument('--pending-timeout', type=float, default=3600)
    parser.add_argument('--approve', action='store_true')
    args = parser.parse_args(argv)
    action = args.prepare_pending or args.select_pending or args.rollback_selection
    if bool(action) != args.approve:
        parser.error('Pending writes require --approve; --approve requires a pending action')
    if args.prepare_pending and not (args.expected_old_sha256 and args.expected_new_sha256):
        parser.error('Preparation requires exact old and new SHA-256 pins')
    if (args.select_pending or args.rollback_selection) and not args.pending_restart_sha256:
        parser.error('Selection/rollback requires an explicit pending receipt pin')
    c = Controller(args.base, control_refresh_sha256=args.control_refresh_sha256,
                   pending_restart_sha256=args.pending_restart_sha256)
    if args.prepare_pending:
        result = prepare(c, args.prepare_pending, expected_old_sha256=args.expected_old_sha256,
                         expected_new_sha256=args.expected_new_sha256, timeout=args.pending_timeout)
    elif args.select_pending:
        result = select(c, args.pending_restart_sha256)
    elif args.rollback_selection:
        with c.locked():
            result = observe(c, args.pending_restart_sha256, rollback=True)
    else:
        result = tick(c)
    print(json.dumps(result))
    return result


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(f'Watchdog stopped without further action: {exc}', file=sys.stderr)
        raise SystemExit(1)
