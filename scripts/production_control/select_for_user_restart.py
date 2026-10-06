#!/usr/bin/env python3
"""Fail-closed user-restart selection scaffold. No installed route is admitted yet.

The current native controller cannot safely represent a selected-but-running-old
pair. --check is an offline source audit, NOT an operational preflight. --select
is deliberately refused until a reviewed pending-ownership controller adapter is
implemented. No command here restarts services or disables the watchdog.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path


class SelectionRefused(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise SelectionRefused(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def audit_routes(old, new, controls):
    """Negative evidence only: do not equate absent bad markers with safety."""
    agent = Path(old['services']['agent']['repo'])
    routes = Path(old['services']['webui']['repo']) / 'api/routes.py'
    gateway = agent / 'hermes_cli/gateway_launchd.py'
    watchdog = Path(controls) / 'watchdog.py'
    files = {str(p): digest(p.read_bytes()) for p in (routes, gateway, watchdog)}
    gateway_text = gateway.read_text()
    watchdog_text = watchdog.read_text()
    blockers = []
    if 'refresh_ok = _gw().refresh_launchd_plist_if_needed()' in gateway_text and 'plist_path.write_text(new_plist' in gateway_text:
        blockers.append('Gateway UI CLI refresh can overwrite the native host plist before restart')
    if old.get('native_host') and old['services']['webui']['argv'] != new['services']['webui']['argv'] and 'c.listener_ownership(manifest, jobs)' in watchdog_text and 'c.host.kickstart' in watchdog_text:
        blockers.append('Selected candidate WebUI argv differs from live fallback: native shallow watchdog ownership fails and may kickstart before user action')
    blockers.append('No reviewed installed pending-user-restart ownership adapter; unknown routes remain refused')
    return {'status': 'blocked', 'changed': False, 'selected_release': old['release_id'],
            'candidate_release': new['release_id'], 'blockers': blockers, 'source_sha256': files}


def select_locked(c, candidate, expected_selected, expected_candidate, backup, receipt,
                  *, atomic_write, save_json, route_gate, approve=False):
    """Transaction kernel for a FUTURE admitted route, tested with disposable hosts.

    c is the sanctioned controller: locked/refresh_admission/read_transaction,
    retained_file, preflight, definitions, loaded, snapshot, revocation checks.
    route_gate MUST prove native pending ownership AND the exact live CLI path.
    The CLI intentionally supplies no permissive implementation of that gate.
    Never modify the controller transaction or its rollback history.
    """
    candidate, backup, receipt = map(Path, (candidate, backup, receipt))
    with c.locked():
        refresh_unchanged = c.refresh_admission()
        txn = c.read_transaction()
        require(txn is not None and txn['phase'] in {'verified', 'rolled_back'},
                'Prior transaction is not verified/rolled_back')
        pinned = {}

        def retain(path):
            path = Path(path)
            pinned[path] = c.retained_file(path)
            return pinned[path][0]

        old_bytes = retain(c.manifest_path)
        new_bytes = retain(candidate)
        require(digest(old_bytes) == expected_selected, 'Selected manifest CAS mismatch')
        require(digest(new_bytes) == expected_candidate, 'Candidate manifest CAS mismatch')
        retain(c.transaction_path)
        old = c.validate_manifest(json.loads(old_bytes))
        new = c.validate_manifest(json.loads(new_bytes))
        require(old['labels'] == new['labels'], 'Service label change requires controlled activation')
        require(old.get('native_host') == new.get('native_host'), 'Native host change requires controlled activation')
        saved = {s: retain(c.plist_path(old, s)) for s in ('agent', 'webui')}
        definitions = c.definitions(old, saved=saved)
        proposed = c.candidate_definitions(old, new, saved, reload=False)
        require(definitions == proposed, 'Definition change requires controlled activation')
        for manifest in (old, new):
            c.check_revocation(manifest)
            c.preflight(manifest)
        before = c.snapshot(old, definitions)
        # This is a mandatory gate, not an operator override or source marker test.
        route_unchanged = route_gate(c, old, new, before)
        require(callable(route_unchanged), 'Missing retained route proof')

        def unchanged():
            refresh_unchanged()
            route_unchanged()
            for path, value in pinned.items():
                require(c.retained_file(path) == value, 'Pinned input changed: ' + str(path))
            for manifest in (old, new):
                c.check_revocation(manifest)
            require(c.snapshot(old, definitions) == before, 'Live fallback/PIDs changed')

        unchanged()
        if not approve:
            return {'status': 'checked', 'changed': False, 'pids': before['pids']}
        require(not backup.exists() and not backup.is_symlink() and
                not receipt.exists() and not receipt.is_symlink(), 'Output already exists')
        require(backup != receipt and backup not in pinned and receipt not in pinned,
                'Output collides with retained input')
        # Backup includes exact selector, plists and transaction, never credentials.
        save_json(backup, {'schema_version': 1, 'selected_sha256': expected_selected,
                          'candidate_sha256': expected_candidate,
                          'files': {str(p): base64.b64encode(v[0]).decode() for p, v in pinned.items()},
                          'fallback': before})
        unchanged()
        result = None
        try:
            atomic_write(c.manifest_path, new_bytes)
            require(c.manifest_path.read_bytes() == new_bytes, 'Selection readback mismatch')
            refresh_unchanged()
            route_unchanged()
            c.preflight(new)
            require(c.snapshot(old, definitions) == before, 'Live fallback/PIDs changed after selection')
            result = {'status': 'selected_pending_user_restart', 'changed': True,
                      'selected_sha256': expected_candidate, 'fallback_sha256': expected_selected,
                      'pids': before['pids'], 'backup': str(backup)}
            save_json(receipt, result)
            require(json.loads(receipt.read_bytes()) == result, 'Receipt readback mismatch')
            return result
        except BaseException:
            # A writer can publish success and then fail (for example at fsync).
            # Invalidate our own receipt before restoring the old selection.
            if result is not None and receipt.exists():
                require(not receipt.is_symlink() and json.loads(receipt.read_bytes()) == result,
                        'Receipt changed; manual reconciliation required')
                atomic_write(receipt, (json.dumps({'status': 'selection_failed_needs_reconciliation',
                                                  'changed': None}) + '\n').encode())
            # Also handles rename-success/fsync-failure. Never overwrite a third party.
            current = c.manifest_path.read_bytes()
            require(current in (new_bytes, old_bytes), 'Rollback CAS refused; manual reconciliation required')
            if current == new_bytes:
                atomic_write(c.manifest_path, old_bytes)
            require(c.manifest_path.read_bytes() == old_bytes, 'Fallback readback failed')
            require(c.snapshot(old, definitions) == before, 'Fallback restored but PIDs changed')
            raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', required=True, type=Path)
    parser.add_argument('--controls', required=True, type=Path)
    parser.add_argument('--candidate', required=True, type=Path)
    parser.add_argument('--expect-selected-sha256', required=True)
    parser.add_argument('--expect-candidate-sha256', required=True)
    parser.add_argument('--select', action='store_true')
    args = parser.parse_args(argv)
    old = (args.base / 'production-release.json').read_bytes()
    new = args.candidate.read_bytes()
    require(digest(old) == args.expect_selected_sha256, 'Selected manifest CAS mismatch')
    require(digest(new) == args.expect_candidate_sha256, 'Candidate manifest CAS mismatch')
    result = audit_routes(json.loads(old), json.loads(new), args.controls)
    # Do not instantiate the controller, acquire a live lock, import applications,
    # or make backups until the fundamental ownership blockers are resolved.
    print(json.dumps(result, indent=2))
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
