#!/usr/bin/env python3
"""Fail-closed macOS candidate canary. Never selects/releases/restarts production.

Uses the existing canary.py's health/asset/restart checks, but deliberately NOT
its launchd/launcher path: that path inherits environment and lacks OS containment.
Only a fresh scratch run directory is writable by candidate processes.
Requires macOS sandbox-exec; fails closed elsewhere. No production service control.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request

BASE = Path(os.environ.get('HERMES_CANARY_SCRATCH', str(Path.home() / '.hermes/cache/scratch')))
ASSETS = ('boot.js', 'ui.js', 'panels.js', 'embed-host.js', 'i18n.js')


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


def inventory(root):
    """All bytes INCLUDING .git and caches; no Git-ignore exemptions."""
    root = Path(root).resolve(strict=True)
    out = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            p = Path(directory) / name
            st = p.lstat()
            key = str(p.relative_to(root))
            if p.is_symlink():
                require(p.resolve(strict=True).is_relative_to(root), 'External symlink: ' + str(p))
                out[key] = ['link', os.readlink(p)]
            elif p.is_file():
                out[key] = ['file', stat.S_IMODE(st.st_mode), st.st_size, digest(p)]
            elif p.is_dir():
                out[key] = ['dir', stat.S_IMODE(st.st_mode)]
            else:
                raise RuntimeError('Special file in candidate: ' + str(p))
    return out


def clean_env(root, agent=None, webui=None, port=None):
    # Construct, never filter/copy os.environ or manifest env/env_files.
    env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'en_US.UTF-8',
           'HOME': str(root / 'home'), 'TMPDIR': str(root / 'tmp'),
           'HERMES_HOME': str(root / 'state'), 'HERMES_BASE_HOME': str(root / 'state'),
           'HERMES_CONFIG_PATH': str(root / 'state/config.yaml'),
           'HERMES_WEBUI_STATE_DIR': str(root / 'webui'),
           'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1',
           'PYTHONSAFEPATH': '1', 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_OPTIONAL_LOCKS': '0'}
    if agent:
        env.update(PYTHONPATH=str(agent), HERMES_WEBUI_AGENT_DIR=str(agent),
                   HERMES_WEBUI_HOST='127.0.0.1', HERMES_WEBUI_PORT=str(port),
                   HERMES_WEBUI_DEFAULT_WORKSPACE=str(root / 'home'),
                   HERMES_WEBUI_PASSWORD='', HERMES_WEBUI_AUTO_INSTALL='0',
                   HERMES_WEBUI_SKIP_ONBOARDING='1', HERMES_WEBUI_TEST_NETWORK_BLOCK='1')
    return env


def sandbox_policy(root, reads, port, executables):
    q = lambda p: json.dumps(str(Path(p).resolve()))
    lines = ['(version 1)', '(allow default)', '(deny file-read-data)',
             '(deny file-write*)', '(deny network*)', '(deny process-exec)',
             '(deny appleevent-send)', '(deny signal)', '(deny mach-lookup)']
    # Public OS/runtime libraries and Apple Git's xcrun dependencies only;
    # never user homes, keychains, browser stores, or a blanket /Library grant.
    for p in ['/System', '/usr', '/bin', '/sbin', '/dev', '/private/preboot', '/private/var/db/dyld', '/Library/Developer/CommandLineTools', *reads, root]:
        lines.append(f'(allow file-read-data (subpath {q(p)}))')
    lines += ['(allow file-read-data (literal "/"))', f'(allow file-write* (subpath {q(root)}))',
              '(allow file-write* (literal "/dev/null"))',
              f'(allow network-bind (local ip "localhost:{port}"))',
              f'(allow network-inbound (local ip "localhost:{port}"))',
              f'(allow network* (subpath {q(root)}))']
    # Python mimetypes consults this public OS database on first static request.
    lines.append('(allow file-read-data (literal "/private/etc/apache2/mime.types"))')
    for p in [*executables, '/usr/bin/git', '/Library/Developer/CommandLineTools/usr/bin/git', '/bin/ps', '/usr/bin/uname']:
        lines.append(f'(allow process-exec (literal {q(p)}))')
    return '\n'.join(lines) + '\n'


def cmd(policy, python, *args):
    return ['/usr/bin/sandbox-exec', '-f', str(policy), str(python), '-B', '-s', *args]


def initialize(root):
    for name in ('home', 'state', 'webui', 'tmp'):
        (root / name).mkdir(mode=0o700)
    config = {'model': {'default': 'canary-no-inference'},
              'gateway': {'multiplex_profiles': False}, 'platforms': {},
              'cron': {'enabled': False}, 'curator': {'enabled': False},
              'kanban': {'dispatch_in_gateway': False},
              'plugins': {'enabled': [], 'disabled': []}, 'mcp_servers': {},
              'memory': {'memory_enabled': False, 'user_profile_enabled': False},
              'terminal': {'cwd': str(root / 'home')},
              'skills': {'sync': {'enabled': False}}}
    # JSON is valid YAML; no third-party dependency in harness.
    (root / 'state/config.yaml').write_text(json.dumps(config))


PROBE = r'''
import errno,json,os,pathlib,socket,subprocess,sys
outside,port=sys.argv[1],int(sys.argv[2]); result={}
for op in ('read','write'):
 try:
  if op=='read': pathlib.Path(outside).read_bytes()
  else: pathlib.Path(outside).write_text('FORBIDDEN')
 except PermissionError: result[op+'_denied']=True
 else: raise RuntimeError(op+' escaped sandbox')
s=socket.socket(); s.settimeout(2)
try: s.connect(('127.0.0.1',port))
except PermissionError: result['other_loopback_denied']=True
except OSError as e:
 if e.errno not in (errno.EPERM,errno.EACCES): raise
 result['other_loopback_denied']=True
else: raise RuntimeError('loopback escaped sandbox')
s.close()
s=socket.socket(); s.settimeout(2)
try: s.connect(('192.0.2.1',443))
except OSError as e:
 if e.errno not in (errno.EPERM,errno.EACCES): raise
 result['external_denied']=True
else: raise RuntimeError('external escaped sandbox')
s.close()
try: subprocess.run(['/bin/sh','-c','exit 0'],check=True)
except PermissionError: result['shell_denied']=True
else: raise RuntimeError('shell execution escaped sandbox')
# Demonstrate child inheritance using the same permitted interpreter.
if not os.environ.get('CANARY_PROBE_CHILD'):
 env=dict(os.environ,CANARY_PROBE_CHILD='1')
 p=subprocess.run([sys.executable,'-B','-s','-c',sys.argv[3],outside,str(port),''],env=env,capture_output=True,text=True)
 if p.returncode: raise RuntimeError('child containment failed: '+p.stderr)
 result['child_inheritance']=json.loads(p.stdout)
print(json.dumps(result))
'''


def prove_isolation(root, python, policy, env):
    outside = root.parent / ('deny-sentinel-' + root.name)
    outside.write_text('nonsecret canary containment sentinel')
    try:
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0)); listener.listen()
            p = subprocess.run(cmd(policy, python, '-c', PROBE, str(outside),
                                   str(listener.getsockname()[1]), PROBE),
                               env=env, cwd=root, capture_output=True, text=True, timeout=30)
        require(p.returncode == 0, f'ISOLATION NOT PROVEN (exit {p.returncode}): ' + p.stderr[-4000:] + p.stdout[-1000:])
        require(outside.read_text() == 'nonsecret canary containment sentinel', 'Sentinel changed')
        return json.loads(p.stdout)
    finally:
        outside.unlink(missing_ok=True)


def git_command(repo, *args):
    # Local/global Git configuration is executable input (fsmonitor, hooks,
    # filters and replacement objects), not source provenance.
    return ['/usr/bin/git', '--no-replace-objects', '-c', 'core.fsmonitor=false',
            '-c', 'core.hooksPath=/dev/null', '-c', 'core.attributesFile=/dev/null',
            '-c', 'core.worktree=' + str(repo), '-C', str(repo), *args]


def tracked_bytes(repo, expected, env):
    result = subprocess.run(git_command(repo, 'ls-tree', '-rz', expected),
                            env=env, capture_output=True, timeout=60)
    require(result.returncode == 0, 'Cannot read committed tree')
    for record in result.stdout.split(b'\0'):
        if not record:
            continue
        metadata, name = record.split(b'\t', 1)
        mode, kind, oid = metadata.split()
        path = repo / os.fsdecode(name)
        require(kind == b'blob' and mode in (b'100644', b'100755', b'120000'),
                'Unsupported source tree entry')
        require(path.parent.resolve().is_relative_to(repo.resolve()), 'Source path escape')
        if mode == b'120000':
            require(path.is_symlink(), 'modified tracked source: ' + str(path))
            data = os.fsencode(os.readlink(path))
        else:
            require(path.is_file() and not path.is_symlink(), 'modified tracked source: ' + str(path))
            require(bool(path.stat().st_mode & 0o111) == (mode == b'100755'), 'modified tracked source mode')
            data = path.read_bytes()
        actual = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest().encode()
        require(actual == oid, 'modified tracked source: ' + str(path))


def validate_git_metadata(repo, env):
    require((repo / '.git').is_dir() and not (repo / '.git').is_symlink(),
            'Authentic self-contained .git required')
    for name in ('objects/info/alternates', 'commondir'):
        require(not (repo / '.git' / name).exists(), 'External Git object dependency')
    inventory(repo / '.git')
    config = subprocess.run(git_command(repo, 'config', '--local', '--no-includes',
                                        '--get-regexp', '^include'),
                            env=env, capture_output=True, timeout=30)
    require(config.returncode == 1, 'External or malformed Git configuration')


def git_identity(repo, expected, env):
    require(len(expected) == 40 and all(c in '0123456789abcdef' for c in expected), 'Invalid SHA')
    validate_git_metadata(repo, env)
    for args in (['rev-parse', 'HEAD'], ['rev-parse', '--verify', expected + '^{commit}']):
        p = subprocess.run(git_command(repo, *args), env=env,
                           capture_output=True, text=True, timeout=30)
        require(p.returncode == 0 and p.stdout.strip() == expected, 'Git identity/object mismatch: ' + str(repo))
    tracked_bytes(repo, expected, env)
    for name in ('.env', 'auth.json', 'config.yaml'):
        require(not (repo / name).exists(), 'Candidate contains state/credential file: ' + name)
    require(not (repo / '.git/objects/info/alternates').exists(), 'External Git alternates forbidden')


def stop(p):
    if p.poll() is None:
        os.killpg(p.pid, signal.SIGTERM)
        try: p.wait(timeout=20)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL); p.wait(timeout=10)
    # Reap any children still in this private session/process group.
    try: os.killpg(p.pid, signal.SIGKILL)
    except ProcessLookupError: pass
    try: os.killpg(p.pid, 0)
    except ProcessLookupError: return
    raise RuntimeError('Canary process group remains after cleanup')


def fetch(port, path):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(f'http://127.0.0.1:{port}' + path, timeout=3) as response:
        require(response.status == 200, 'HTTP status not 200')
        return response.read()


def wait_ready(gateway, webui, root, port, expected):
    deadline = time.monotonic() + 90
    last = ''
    while time.monotonic() < deadline:
        require(gateway.poll() is None and webui.poll() is None, 'Candidate exited; inspect run logs')
        try:
            state = json.loads((root / 'state/gateway_state.json').read_text())
            require(state.get('pid') == gateway.pid, 'Gateway PID mismatch')
            require(state.get('code_sha') == expected, 'Actual gateway code_sha mismatch')
            require(state.get('gateway_state') == 'running', 'Gateway not running')
            require(not state.get('platforms'), 'Unexpected messaging platform enabled')
            require(Path(state['hermes_home']).resolve() == (root / 'state').resolve(), 'Gateway home mismatch')
            health = json.loads(fetch(port, '/health?deep=1'))
            require(health.get('status') == 'ok', 'WebUI not healthy')
            listeners = subprocess.run(['/usr/sbin/lsof', '-nP', '-a', '-p', str(webui.pid),
                                        '-iTCP', '-sTCP:LISTEN', '-Fn'], capture_output=True, text=True, timeout=5)
            names = [x[1:] for x in listeners.stdout.splitlines() if x.startswith('n')]
            require(names == [f'127.0.0.1:{port}'], 'Listener owner/address mismatch')
            return {'gateway_pid': gateway.pid, 'webui_pid': webui.pid,
                    'gateway_state': state, 'health': health}
        except (OSError, ValueError, RuntimeError) as e:
            last = str(e)
        time.sleep(.3)
    raise RuntimeError('Readiness timeout: ' + last)


def run(args):
    # Refuse an artifact-owned scratch directory before creating any state there.
    for value in (args.runtime, args.agent, args.webui):
        if value:
            require(not BASE.resolve().is_relative_to(Path(value).resolve()),
                    'Scratch directory is inside candidate payload')
    BASE.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix='canary-', dir=BASE))
    require(len(os.fsencode(root / 'state/gateway.sock')) < 104, 'Scratch path too long for AF_UNIX')
    initialize(root)
    report = {'status': 'failed', 'run': str(root), 'production_touched': False,
              'native_host_tested': False, 'message_delivery_tested': False, 'events': []}
    children = []; logs = []; baseline = None; roots = []
    try:
        python = Path(args.python).absolute()
        runtime = Path(args.runtime).resolve(strict=True)
        require(runtime.name == 'runtime' and python == runtime / 'venv/bin/python',
                'Canary requires a private runtime/venv/bin/python layout')
        require(python.resolve(strict=True).is_relative_to(runtime), 'Interpreter must be inside supplied runtime')
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]
        agent = Path(args.agent).resolve(strict=True) if args.agent else None
        webui = Path(args.webui).resolve(strict=True) if args.webui else None
        if agent or webui:
            require(agent == runtime.parent / 'agent' and webui == runtime.parent / 'webui',
                    'Canary source roots must be siblings of private runtime')
        roots = [runtime] + ([agent, webui] if agent and webui else [])
        baseline = {str(p): inventory(p) for p in roots}
        require(all(not root.is_relative_to(p) and not p.is_relative_to(root) for p in roots), 'Run/release overlap')
        env = clean_env(root, agent, webui, port)
        policy = root / 'sandbox.sb'
        policy.write_text(sandbox_policy(root, roots, port, [python, python.resolve()]))
        if not args.isolation_only:
            require(agent is not None and webui is not None, '--agent and --webui required')
            git_identity(agent, args.agent_sha, env); git_identity(webui, args.webui_sha, env)
            report['baseline_counts'] = {p: len(v) for p,v in baseline.items()}
            report['baseline_digests'] = {p: hashlib.sha256(json.dumps(v,sort_keys=True).encode()).hexdigest() for p,v in baseline.items()}
        report['isolation'] = prove_isolation(root, python, policy, env)
        if args.isolation_only:
            report['status'] = 'isolation_proven'
            return report
        for cycle in ('cold_start', 'process_restart'):
            for name, cwd, argv in [('gateway', agent, ['-m', 'hermes_cli.main', 'gateway', 'run', '--external-supervisor']),
                                    ('webui', webui, [str(webui / 'server.py')])]:
                log = (root / (cycle + '-' + name + '.log')).open('wb'); logs.append(log)
                child_env = dict(env, PYTHONPATH=os.pathsep.join(dict.fromkeys([str(cwd), str(agent)])))
                child = subprocess.Popen(cmd(policy, python, *argv), env=child_env, cwd=cwd,
                                         stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                         start_new_session=True)
                children.append(child)
            event = wait_ready(*children, root, port, args.agent_sha)
            event['event'] = cycle
            event['assets'] = {}
            for name in ASSETS:
                actual = hashlib.sha256(fetch(port, '/static/' + name)).hexdigest()
                require(actual == digest(webui / 'static' / name), 'Served asset mismatch: ' + name)
                event['assets'][name] = actual
            report['events'].append(event)
            require(all(inventory(p) == baseline[str(p)] for p in roots), 'Inventory drift after boot')
            for child in reversed(children): stop(child)
            children.clear()
            listeners = subprocess.run(['/usr/sbin/lsof', '-nP', '-iTCP:' + str(port),
                                        '-sTCP:LISTEN', '-t'], capture_output=True, text=True, timeout=5)
            require(not listeners.stdout.strip(), 'Listener survives canary cleanup')
            require(all(inventory(p) == baseline[str(p)] for p in roots), 'Inventory drift after stop')
        report['status'] = 'passed'
        return report
    except BaseException as e:
        report['error'] = str(e)
        raise
    finally:
        errors = []
        for p in reversed(children):
            try: stop(p)
            except Exception as e: errors.append(str(e))
        for log in logs: log.close()
        if baseline is not None:
            try:
                report['inventory_unchanged'] = all(inventory(p) == baseline[str(p)] for p in roots)
                if not report['inventory_unchanged']: errors.append('final inventory drift')
            except Exception as e: errors.append(str(e))
        # Retain logs/policy/receipt; remove only disposable HOME and mutable application state.
        for name in ('home', 'state', 'webui', 'tmp'):
            shutil.rmtree(root / name)
        report['cleanup'] = {'state_removed': True, 'errors': errors}
        if errors: report['status'] = 'failed'
        (root / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(str(root / 'report.json'), flush=True)
        if errors: raise RuntimeError('; '.join(errors))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--python', required=True)
    p.add_argument('--runtime', required=True)
    p.add_argument('--agent'); p.add_argument('--webui')
    p.add_argument('--agent-sha', required=True); p.add_argument('--webui-sha', required=True)
    p.add_argument('--isolation-only', action='store_true')
    args = p.parse_args()
    run(args)


if __name__ == '__main__':
    main()
