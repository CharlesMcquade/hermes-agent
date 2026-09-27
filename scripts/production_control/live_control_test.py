#!/usr/bin/env python3
"""Real launchd controller fault injection using explicitly synthetic services.

Tests the controller, not Hermes application behavior (canary.py covers WebUI).
All state/labels/ports are disposable; no production paths or credentials used.
"""
import json
import os
from pathlib import Path
import plistlib
import socket
import subprocess
import sys
import tempfile
import time

from production_launcher import inventory
from restart_production import Controller, ASSETS, save_json

AGENT = '''import json,os,pathlib,time
p=pathlib.Path(os.environ['TEST_STATE'])/'gateway_state.json'
p.write_text(json.dumps({'pid':os.getpid(),'gateway_state':'running','code_sha':os.environ['TEST_SHA'],'updated_at':time.time()}))
while True: time.sleep(1)
'''
WEBUI = '''import http.server,json,os,pathlib,time
started=time.time()
class H(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  if self.path.startswith('/health'): data=json.dumps({'status':'ok','server_started_at':started}).encode()
  elif self.path.startswith('/static/'): data=(pathlib.Path.cwd()/self.path.lstrip('/')).read_bytes()
  else: self.send_error(404); return
  self.send_response(200); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
 def log_message(self,*args): pass
http.server.ThreadingHTTPServer(('127.0.0.1',int(os.environ['TEST_PORT'])),H).serve_forever()
'''


def main():
    with tempfile.TemporaryDirectory(prefix='hermes-control-fault-') as directory:
        base = Path(directory)
        launcher_source = Path(__file__).with_name('production_launcher.py')
        (base / 'production_launcher.py').write_bytes(launcher_source.read_bytes())
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        labels = {s: f'com.charles.hermes-control-test.{os.getpid()}.{s}' for s in ('agent', 'webui')}
        manifest = {'schema_version': 2, 'labels': labels, 'state_dir': str(base),
                    'health_url': f'http://127.0.0.1:{port}/health', 'services': {}}
        for service, text in [('agent', AGENT), ('webui', WEBUI)]:
            repo = base / service
            repo.mkdir()
            (repo / 'main.py').write_text(text)
            if service == 'webui':
                (repo / 'static').mkdir()
                for name in ASSETS: (repo / 'static' / name).write_text('synthetic-test-asset')
            plist = base / (service + '.plist')
            manifest['services'][service] = {'repo': str(repo), 'cwd': str(repo), 'commit': 'fixture-old',
                'argv': [sys.executable, '-B', str(repo / 'main.py')], 'inventory': inventory(repo),
                'env': {'TEST_STATE': str(base), 'TEST_PORT': str(port), 'TEST_SHA': 'fixture-old'},
                'plist_path': str(plist)}
            plist.write_bytes(plistlib.dumps({'Label': labels[service],
                'ProgramArguments': [sys.executable, str(base / 'production_launcher.py'), service],
                'WorkingDirectory': str(base), 'RunAtLoad': True, 'KeepAlive': True, 'ThrottleInterval': 1,
                'StandardOutPath': str(base / (service + '.out')), 'StandardErrorPath': str(base / (service + '.err'))}))
        save_json(base / 'production-release.json', manifest)
        domain = f'gui/{os.getuid()}'
        loaded = []
        proof = {}
        try:
            for service in labels:
                subprocess.run(['/bin/launchctl', 'bootstrap', domain, str(base / (service + '.plist'))], check=True)
                loaded.append(domain + '/' + labels[service])
            c = Controller(base, timeout=8, stable_seconds=1)
            before = {s: {'pid': None} for s in labels}
            c.wait_ready(manifest, c.definitions(manifest), time.time() - 10, before)
            proof['routine_restart'] = c.restart(confirm=lambda: True)
            if proof['routine_restart']['status'] != 'verified': raise RuntimeError(proof)
            candidate = json.loads(json.dumps(manifest))
            broken = base / 'broken-webui'
            broken.mkdir()
            (broken / 'main.py').write_text('raise SystemExit(9)\n')
            item = candidate['services']['webui']
            item.update(repo=str(broken), cwd=str(broken), inventory=inventory(broken),
                        argv=[sys.executable, '-B', str(broken / 'main.py')], commit='fixture-bad')
            candidate_path = base / 'candidate.json'
            save_json(candidate_path, candidate)
            proof['failed_activation'] = c.restart(candidate_path, confirm=lambda: True)
            if proof['failed_activation']['status'] != 'rolled_back': raise RuntimeError(proof)
            if c.load() != manifest: raise RuntimeError('Rollback failed to restore manifest')
            # Byte tamper must refuse BEFORE launchctl is called; prove actual PIDs stay.
            before = {s: c.host.job(c.target(manifest, s))['pid'] for s in labels}
            (base / 'webui' / 'main.py').write_text(WEBUI + '\n# unexpected edit\n')
            try:
                c.restart(confirm=lambda: True)
            except RuntimeError as exc:
                proof['tamper_refusal'] = str(exc)
            else: raise RuntimeError('Expected refusal')
            after = {s: c.host.job(c.target(manifest, s))['pid'] for s in labels}
            if after != before: raise RuntimeError('Preflight failure interrupted live fixture')
            proof.update(status='passed', synthetic_services=True, production_services_touched=False)
            output = Path(sys.argv[1])
            output.write_text(json.dumps(proof, indent=2) + '\n')
            print(json.dumps(proof, indent=2))
        finally:
            for target in reversed(loaded):
                subprocess.run(['/bin/launchctl', 'bootout', '--wait', target], capture_output=True, timeout=30)
                if subprocess.run(['/bin/launchctl', 'print', target], capture_output=True).returncode == 0:
                    raise RuntimeError('Leaked synthetic service: ' + target)


if __name__ == '__main__':
    main()
