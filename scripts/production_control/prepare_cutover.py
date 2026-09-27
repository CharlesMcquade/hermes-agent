#!/usr/bin/env python3
"""Stage a one-shot explicit cutover; never bootstrap, kickstart, or stop a job."""
import argparse
import json
import os
from pathlib import Path
import plistlib
import sys

from restart_production import Controller, save_json, atomic_write


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--output-plist', type=Path, required=True)
    args = parser.parse_args()
    base = args.base.resolve()
    c = Controller(base)
    old = c.load()
    new = c.load(args.candidate)
    c.preflight(old)
    c.preflight(new)
    c.snapshot(old, c.definitions(old))
    python = new['services']['agent']['argv'][0]
    overrides = {}
    for service in ('agent', 'webui'):
        current = plistlib.loads(c.plist_path(old, service).read_bytes())
        env = dict(current.get('EnvironmentVariables', {}))
        for name in ('PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP'):
            env.pop(name, None)
        env.update(HOME=str(Path.home()), PYTHONDONTWRITEBYTECODE='1',
                   PYTHONSAFEPATH='1', PYTHONNOUSERSITE='1')
        overrides[service] = {'ProgramArguments': [python, str(base / 'production_launcher.py'), service],
                              'WorkingDirectory': old['state_dir'], 'EnvironmentVariables': env}
    new['launchd_overrides'] = overrides
    candidate = base / 'candidate-release.json'
    save_json(candidate, new)
    saved = {s: c.plist_path(old, s).read_bytes() for s in ('agent', 'webui')}
    c.candidate_definitions(old, new, saved, reload=True)
    # This runner is directly parented by launchd. A finite handoff permits the
    # tool response to arrive before WebUI goes away; no child-service ownership.
    runner = base / 'resilient_cutover_job.py'
    code = f'''import os,sys,time,runpy
if os.getppid()!=1: raise SystemExit('Independent launchd owner required')
print('Explicit cutover accepted; 15 second handoff',flush=True)
time.sleep(15)
sys.argv=[{str(base / 'approved_restart_job.py')!r},'--restart','--yes','--activate',{str(candidate)!r},'--reload']
runpy.run_path(sys.argv[0],run_name='__main__')
'''
    atomic_write(runner, code.encode())
    definition = {'Label': 'com.charles.hermes-resilient-cutover',
                  'ProgramArguments': [python, '-B', str(runner)],
                  'WorkingDirectory': str(base), 'RunAtLoad': False, 'KeepAlive': False,
                  'EnvironmentVariables': {'HOME': str(Path.home()),
                    'PATH': '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin',
                    'PYTHONDONTWRITEBYTECODE': '1'},
                  'StandardOutPath': str(base / 'resilient-cutover.log'),
                  'StandardErrorPath': str(base / 'resilient-cutover.err.log')}
    atomic_write(args.output_plist, plistlib.dumps(definition))
    print(json.dumps({'status': 'staged_not_loaded', 'plist': str(args.output_plist),
                      'candidate': str(candidate), 'release': new['release_id']}))


if __name__ == '__main__':
    main()
