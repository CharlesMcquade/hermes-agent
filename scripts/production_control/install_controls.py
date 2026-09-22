#!/usr/bin/env python3
"""Install versioned restart controls without stopping or starting a service.

Stage a dual-schema bridge first, then atomically publish a frozen known-good
manifest. An interrupted install always leaves a launcher able to read whichever
manifest is present. The old exact-SHA guard remains available for schema 1 only.
This does not activate candidate application code or reload launchd definitions.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import sys

from production_launcher import preflight
from restart_production import atomic_write, control_lock, save_json

FILES = ('production_launcher.py', 'restart_production.py', 'watchdog.py', 'approved_restart_job.py')


def install(base, baseline, control_id):
    base = base.resolve()
    current = base / 'production-release.json'
    data = json.loads(baseline.read_text())
    preflight(data)
    if not control_id or not all(c.isalnum() or c in '-_' for c in control_id):
        raise ValueError('Invalid control version')
    bundle = base / 'control-versions' / control_id
    with control_lock(base):
        old = json.loads(current.read_text())
        if old.get('schema_version') != 1:
            raise RuntimeError('Migration requires legacy schema 1; use release activation for subsequent deployments')
        bundle.mkdir(parents=True, exist_ok=False)
        for name in FILES:
            shutil.copyfile(Path(__file__).with_name(name), bundle / name)
        legacy = base / 'production_launcher.py'
        shutil.copyfile(legacy, bundle / 'legacy_launcher.py')
        (bundle / 'legacy-manifest.json').write_bytes(current.read_bytes())
        receipt = {name: hashlib.sha256((bundle / name).read_bytes()).hexdigest() for name in FILES}
        (bundle / 'control-receipt.json').write_text(json.dumps(receipt, indent=2))
        for path in bundle.iterdir():
            path.chmod(0o444)
        bundle.chmod(0o555)
        # Wrappers import ONLY the immutable control bundle, while data remains
        # under maintenance. Every replacement is fsync + rename, no partial file.
        prefix = ('#!/usr/bin/env python3\nimport sys\nfrom pathlib import Path\n'
                  f'sys.path.insert(0, {str(bundle)!r})\nBASE=Path({str(base)!r})\n')
        bridge = prefix + '''import json
try:
    data=json.loads((BASE/'production-release.json').read_text())
    if data.get('schema_version') == 1:
        import legacy_launcher as launcher
    elif data.get('schema_version') == 2:
        import production_launcher as launcher
    else:
        raise RuntimeError('Unsupported production manifest')
    launcher.MANIFEST=BASE/'production-release.json'
    launcher.main()
except Exception as exc:
    print(f'PRODUCTION START REFUSED: {exc}',file=sys.stderr,flush=True)
    raise SystemExit(78)
'''
        atomic_write(legacy, bridge.encode())
        for name, module in [('restart_production.py', 'restart_production'),
                             ('watchdog.py', 'watchdog'), ('approved_restart_job.py', 'approved_restart_job')]:
            wrapper = prefix + f'''import json
from {module} import main
try:
    result=main(['--base',str(BASE)]+sys.argv[1:])
    print(json.dumps(result))
    raise SystemExit(0 if result.get('status') in ('checked','verified','healthy','grace','suspect','cooldown','degraded','busy','restart_requested') else 1)
except Exception as exc:
    print(str(exc),file=sys.stderr)
    raise SystemExit(1)
'''
            atomic_write(base / name, wrapper.encode())
        frozen_python = data['services']['agent']['argv'][0]
        watchdog = f'#!/bin/sh\nexec {frozen_python} -B {base}/watchdog.py >> {base}/webui-watchdog.log 2>&1\n'
        # Pointer is the commit point. Before this, bridge retains schema-1 behavior.
        save_json(current, data)
        atomic_write(base / 'webui-watchdog.sh', watchdog.encode())
        (base / 'webui-watchdog.sh').chmod(0o755)
        state = Path(data['state_dir'])
        for service in ('agent', 'webui'):
            p = Path(data['services'][service]['plist_path'])
            definition = plistlib.loads(p.read_bytes())
            definition['HermesServiceManager'] = {
                'description': 'Frozen release manager owns this definition; use maintenance/restart_production.py',
                'preflight': [frozen_python, str(base / 'production_launcher.py'), service, '--check']}
            atomic_write(p, plistlib.dumps(definition))
        save_json(state / 'webui/service-manager.json', {'webui_restart_preflight':
                  [frozen_python, str(base / 'production_launcher.py'), 'webui', '--check']})
        result = {'status': 'installed_not_restarted', 'bundle': str(bundle),
                  'baseline': str(baseline), 'control_sha256': receipt}
        save_json(base / 'control-install.json', result)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--control-id', required=True)
    args = parser.parse_args()
    print(json.dumps(install(args.base, args.baseline, args.control_id)))


if __name__ == '__main__':
    main()
