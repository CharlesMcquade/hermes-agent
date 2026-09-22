#!/usr/bin/env python3
"""One conservative WebUI watchdog tick. Schedule externally; never installs jobs."""
import argparse
import json
from pathlib import Path
import sys

from restart_production import BASE, Controller, ControlError, control_lock, save_json


def tick(controller, grace=90, cooldown=300, max_backoff=3600):
    """Only shallow liveness failures justify a restart; deep failures are degraded."""
    path = controller.base / 'watchdog-state.json'
    try:
        with control_lock(controller.base):
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
        manifest = c.load()
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
        if c.host.listener(manifest['health_url']) != {pid}:
            raise ControlError('WebUI listener identity mismatch')
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
    # Persist the attempt BEFORE a side effect: a killed watchdog cannot hot-loop.
    attempts = min(8, state.get('attempts', 0) + 1)
    finish('checking', attempts=attempts,
           next_attempt=now + min(max_backoff, cooldown * 2 ** (attempts - 1)))
    try:
        c.preflight(manifest)
        c.loaded(manifest, definitions)
        c.host.kickstart(c.target(manifest, 'webui'))
    except Exception as exc:
        return finish('blocked', error=str(exc))
    # This records an attempt, never unearned readiness proof; next ticks verify.
    return finish('restart_requested', failures=0, first_seen=now)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, default=BASE)
    args = parser.parse_args(argv)
    result = tick(Controller(args.base))
    print(json.dumps(result))
    return result


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(f'Watchdog stopped without further action: {exc}', file=sys.stderr)
        raise SystemExit(1)
