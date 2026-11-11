#!/usr/bin/env python3
"""Explicitly authorized one-shot entrypoint; must be directly launchd-owned.

Does not create/submit its own job or grant approval. --restart --yes are still
required; pass --activate/--reload only when the user approved that operation.
--return-baseline INSTALL_RECEIPT_SHA256 is a distinct, separately approved
--reload operation. It uses only the retained installed baseline, never arbitrary
restore paths or an edited transaction phase.
The controller's durable journal is authoritative, including rollback outcomes.
"""
import json
import os
import sys

from restart_production import ControlError, main as restart_main
from cutover_guard import require_out_of_process, require_python311


def main(argv=None, owner=os.getppid, ancestry=None):
    require_python311()
    if owner() != 1:
        raise ControlError('Approved restart job must be directly launchd-owned')
    require_out_of_process(parent=owner, **({} if ancestry is None else {'ancestry': ancestry}))
    arguments = list(sys.argv[1:] if argv is None else argv)
    if '--restart' not in arguments or '--yes' not in arguments:
        raise ControlError('Explicit --restart --yes approval flags are required')
    return restart_main(arguments)


if __name__ == '__main__':
    try:
        result = main()
        print(json.dumps(result))
        raise SystemExit(0 if result['status'] == 'verified' else 1)
    except Exception as exc:
        print(f'Approved restart failed: {exc}', file=sys.stderr)
        raise SystemExit(1)
