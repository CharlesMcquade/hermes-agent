#!/usr/bin/env python3
"""Exercise an actual frozen WebUI under a disposable launchd job and HOME.

No production label, credentials, session database, or messaging adapters are
used. The canary listens only on an OS-selected loopback port and cleans up its
own label in finally. This tests process recovery, not messaging delivery.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import signal
import sys
import urllib.error
import socket
import subprocess
import tempfile
import time
import urllib.request


def command(*args):
    return subprocess.run(args, capture_output=True, text=True, timeout=30)


def pid(target):
    result = command('/bin/launchctl', 'print', target)
    match = re.search(r'^\s*pid = (\d+)\s*$', result.stdout, re.M)
    return int(match.group(1)) if match else None


def fetch(url, path):
    with urllib.request.urlopen(url + path, timeout=3) as response:
        return response.read()


def await_ready(target, url, previous=None):
    deadline = time.monotonic() + 60
    error = ''
    while time.monotonic() < deadline:
        current = pid(target)
        if current and current != previous:
            try:
                health = json.loads(fetch(url, '/health?deep=1'))
                if health.get('status') == 'ok':
                    listener = command('/usr/sbin/lsof', '-nP', '-iTCP:' + url.rsplit(':', 1)[1],
                                       '-sTCP:LISTEN', '-t').stdout.strip()
                    if listener == str(current):
                        return current, health
            except Exception as exc:
                error = str(exc)
        time.sleep(.5)
    raise RuntimeError('Canary did not become ready: ' + error)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--test-api', action='store_true')
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    item = manifest['services']['webui']
    repo = Path(item['repo'])
    with tempfile.TemporaryDirectory(prefix='hermes-restart-canary-') as directory:
        root = Path(directory)
        (root / 'config.yaml').write_text('model:\n  default: test-model\ngateway:\n  enabled: false\ncron:\n  enabled: false\n')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        url = f'http://127.0.0.1:{port}'
        env = {k: v for k, v in item['env'].items() if k in {'PYTHONPATH', 'PATH', 'HERMES_WEBUI_AGENT_DIR', 'VIRTUAL_ENV'}}
        env.update(HOME=str(root), HERMES_HOME=str(root), HERMES_BASE_HOME=str(root),
                   HERMES_CONFIG_PATH=str(root / 'config.yaml'), HERMES_WEBUI_STATE_DIR=str(root / 'webui'),
                   HERMES_WEBUI_HOST='127.0.0.1', HERMES_WEBUI_PORT=str(port),
                   HERMES_WEBUI_DEFAULT_WORKSPACE=str(root), HERMES_WEBUI_PASSWORD='',
                   HERMES_WEBUI_TEST_NETWORK_BLOCK='1', HERMES_WEBUI_AUTO_INSTALL='0',
                   HERMES_WEBUI_SKIP_ONBOARDING='1', PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1')
        label = f'com.charles.hermes-restart-canary.{os.getpid()}'
        domain = f'gui/{os.getuid()}'
        target = domain + '/' + label
        # Exercise the real launcher too, not just the server argv.
        isolated = json.loads(json.dumps(manifest))
        isolated['services']['webui'].update(env=env, env_files=[])
        manifest_path = root / 'production-release.json'
        manifest_path.write_text(json.dumps(isolated))
        launcher = root / 'production_launcher.py'
        launcher.write_bytes(Path(__file__).with_name('production_launcher.py').read_bytes())
        state = root / 'webui'
        state.mkdir()
        (state / 'service-manager.json').write_text(json.dumps({
            'webui_restart_preflight': [sys.executable, str(launcher), 'webui', '--check']}))
        plist = root / 'canary.plist'
        plist.write_bytes(plistlib.dumps({'Label': label, 'ProgramArguments': [sys.executable, str(launcher), 'webui'],
            'WorkingDirectory': str(repo), 'EnvironmentVariables': env, 'RunAtLoad': True,
            'KeepAlive': True, 'ThrottleInterval': 1, 'StandardOutPath': str(root / 'out.log'),
            'StandardErrorPath': str(root / 'err.log')}))
        events = []
        started = time.monotonic()
        try:
            result = command('/bin/launchctl', 'bootstrap', domain, str(plist))
            if result.returncode:
                raise RuntimeError('Canary bootstrap failed: ' + result.stderr)
            current, health = await_ready(target, url)
            events.append({'event': 'cold_start', 'pid': current, 'status': health['status']})
            for name in ('boot.js', 'ui.js', 'panels.js', 'embed-host.js', 'i18n.js'):
                if hashlib.sha256(fetch(url, '/static/' + name)).digest() != hashlib.sha256((repo / 'static' / name).read_bytes()).digest():
                    raise RuntimeError('Canary served-file mismatch: ' + name)
            for signum, event in ((signal.SIGTERM, 'graceful_restart'), (signal.SIGKILL, 'crash_recovery')):
                before = current
                os.kill(before, signum)
                current, health = await_ready(target, url, before)
                events.append({'event': event, 'old_pid': before, 'pid': current, 'status': health['status']})
            if args.test_api:
                def post_restart():
                    request = urllib.request.Request(url + '/api/webui/restart', data=b'{}',
                        headers={'Content-Type': 'application/json', 'Origin': url})
                    try:
                        with urllib.request.urlopen(request, timeout=40) as response:
                            return response.status, json.loads(response.read())
                    except urllib.error.HTTPError as exc:
                        return exc.code, json.loads(exc.read())
                broken = json.loads(json.dumps(isolated))
                broken['services']['webui']['inventory'] = {'rejected': {'sha256': 'wrong'}}
                manifest_path.write_text(json.dumps(broken))
                status, data = post_restart()
                if status != 503 or data.get('ok') is not False or pid(target) != current:
                    raise RuntimeError('API preflight did not preserve running service: ' + str((status, data)))
                events.append({'event': 'api_refusal_preserved_pid', 'pid': current, 'status': status})
                manifest_path.write_text(json.dumps(isolated))
                status, data = post_restart()
                if status != 200 or data.get('status') != 'restarting':
                    raise RuntimeError('API restart not accepted: ' + str((status, data)))
                before = current
                current, health = await_ready(target, url, before)
                events.append({'event': 'api_restart_verified', 'old_pid': before, 'pid': current, 'status': health['status']})
            receipt = {'status': 'passed', 'manifest': str(args.manifest), 'release_id': manifest.get('release_id'),
                       'events': events, 'served_assets': 5, 'elapsed_seconds': round(time.monotonic() - started, 2),
                       'production_services_touched': False, 'messaging_delivery_tested': False}
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(receipt, indent=2) + '\n')
            print(json.dumps(receipt, indent=2))
        finally:
            command('/bin/launchctl', 'bootout', '--wait', target)
            check = command('/bin/launchctl', 'print', target)
            if check.returncode == 0:
                raise RuntimeError('Canary cleanup failed: disposable label still loaded')


if __name__ == '__main__':
    main()
