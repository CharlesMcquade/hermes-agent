#!/usr/bin/env python3
"""Opt-in real-process rehearsal, macOS only. Run this file directly with -I -B.

No production imports/signals/selection. All application and publisher execution
is sandboxed. Fake inference is a deterministic HTTP peer, not a fake worker.
Evidence is retained under scratch. Controller/native-host admission is NOT tested.
"""
import hashlib
import http.server
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import candidate_canary as canary

RELEASE = Path('/Users/charles/.hermes/releases/hermes-20261026-redeploy-continuation-r2')
WEBUI = Path('/Users/charles/hermes-dev/worktrees/safe-redeploy-webui')


def run():
    root = Path(tempfile.mkdtemp(prefix='cp-', dir=canary.BASE)).resolve()
    print('EVIDENCE=' + str(root), flush=True)
    report = {'status': 'failed', 'limits': ['No installed controller, native host, gateway restart, production selection, or real provider tested'], 'events': []}
    processes, logs, requests = [], [], []
    fake = None
    try:
        canary.initialize(root)
        class Endpoint(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                data = json.dumps({'object': 'list', 'data': [{'id': 'rehearsal-model', 'object': 'model', 'owned_by': 'test'}]}).encode()
                self.send_response(200); self.send_header('Content-Type', 'application/json'); self.send_header('Content-Length', str(len(data))); self.end_headers(); self.wfile.write(data)
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                requests.append({'path': self.path, 'body': body})
                (root / 'inference.json').write_text(json.dumps(requests, indent=2))
                text = 'REHEARSAL_RESPONSE_OK'
                base = {'id': 'chatcmpl-rehearsal', 'object': 'chat.completion', 'created': 1, 'model': 'rehearsal-model'}
                if body.get('stream'):
                    base['object'] = 'chat.completion.chunk'
                    chunks = [dict(base, choices=[{'index': 0, 'delta': {'role': 'assistant', 'content': text}, 'finish_reason': None}]), dict(base, choices=[{'index': 0, 'delta': {}, 'finish_reason': 'stop'}], usage={'prompt_tokens': 10, 'completion_tokens': 5, 'total_tokens': 15})]
                    data = (''.join('data: ' + json.dumps(x) + '\n\n' for x in chunks) + 'data: [DONE]\n\n').encode()
                    content = 'text/event-stream'
                else:
                    data = json.dumps(dict(base, choices=[{'index': 0, 'message': {'role': 'assistant', 'content': text}, 'finish_reason': 'stop'}], usage={'prompt_tokens': 10, 'completion_tokens': 5, 'total_tokens': 15})).encode()
                    content = 'application/json'
                self.send_response(200); self.send_header('Content-Type', content); self.send_header('Content-Length', str(len(data))); self.end_headers(); self.wfile.write(data)
        fake = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Endpoint)
        threading.Thread(target=fake.serve_forever, daemon=True).start()
        inference_port = fake.server_address[1]
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]
        agent, runtime = RELEASE / 'agent', RELEASE / 'runtime'
        python = runtime / 'venv/bin/python'
        env = canary.clean_env(root, agent, WEBUI, port)
        env.update(PYTHONPATH=str(WEBUI) + ':' + str(agent), HERMES_WEBUI_CONTINUATION_DIR=str(root / 'private'), HERMES_WEBUI_RUNTIME_ADAPTER='legacy-direct', HERMES_WEBUI_CHAT_BACKEND='legacy', OPENAI_API_KEY='isolated-dummy', OPENAI_BASE_URL=f'http://127.0.0.1:{inference_port}/v1')
        env.pop('HERMES_WEBUI_TEST_NETWORK_BLOCK', None)
        config = json.loads((root / 'state/config.yaml').read_text())
        config['model'] = {'default': 'rehearsal-model', 'provider': 'custom', 'base_url': env['OPENAI_BASE_URL'], 'api_key': 'isolated-dummy'}
        config['compression'] = {'enabled': False}
        (root / 'state/config.yaml').write_text(json.dumps(config))
        policy = root / 'sandbox.sb'
        policy.write_text(canary.sandbox_policy(root, [agent, runtime, WEBUI, HERE], port, [python, python.resolve()]) + f'(allow network-outbound (remote ip "localhost:{inference_port}"))\n')
        # Store traverses each ancestor with openat(O_DIRECTORY); grant only
        # directory objects, never their contents recursively.
        with policy.open('a') as f:
            for ancestor in root.parents:
                f.write('(allow file-read-data (literal ' + json.dumps(str(ancestor)) + '))\n')
        report['isolation'] = canary.prove_isolation(root, python, policy, env)
        files = ('server.py', 'api/routes.py', 'api/post_restart_continuation.py', 'api/runtime_adapter.py', 'api/streaming.py')
        hashes = {name: {'sha256': canary.digest(WEBUI / name)} for name in files}
        revision = subprocess.check_output(['/usr/bin/git', '-C', str(WEBUI), 'rev-parse', 'HEAD'], text=True).strip()
        (root / 'manifest.json').write_text(json.dumps({'services': {'webui': {'repo': str(WEBUI), 'commit': revision, 'inventory': hashes}}}))
        report['execution_inventory'] = hashes
        def publish(action, *extra):
            p = subprocess.run(canary.cmd(policy, python, str(HERE / 'continuation_process_publish.py'), str(root), str(WEBUI), action, *extra), cwd=root, env=env, capture_output=True, text=True, timeout=20)
            (root / ('publisher-' + action + '.log')).write_text(p.stdout + p.stderr)
            canary.require(p.returncode == 0, 'Publisher ' + action + ' failed: ' + p.stderr)
        publish('initialize')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        def request_http(path, body=None):
            req = urllib.request.Request(f'http://127.0.0.1:{port}' + path, data=None if body is None else json.dumps(body).encode(), headers={'Content-Type': 'application/json', 'Origin': f'http://127.0.0.1:{port}'})
            with opener.open(req, timeout=10) as r: return json.load(r)
        def wait(fn, label, seconds=45):
            end = time.monotonic() + seconds
            last = None
            while time.monotonic() < end:
                try:
                    value = fn()
                    if value: return value
                except (OSError, ValueError, sqlite3.OperationalError) as e: last = str(e)
                if processes and processes[-1].poll() is not None: raise RuntimeError('Server exited: ' + label)
                if label == 'continuation real inference':
                    trace = root / 'relaunch-consumer.jsonl'
                    if trace.exists() and 'refused_or_ambiguous' in trace.read_text():
                        raise RuntimeError('Real startup consumer refused; see relaunch-consumer.jsonl')
                time.sleep(.3)
            raise RuntimeError('Timeout: ' + label + '; ' + str(last))
        def start(label):
            log = (root / (label + '.log')).open('wb'); logs.append(log)
            child = subprocess.Popen(canary.cmd(policy, python, str(HERE / 'continuation_process_server.py'), str(WEBUI), str(root / (label + '-consumer.jsonl'))), cwd=WEBUI, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            processes.append(child)
            health = wait(lambda: request_http('/health?deep=1'), label)
            canary.require(health.get('status') == 'ok', 'Unhealthy server')
            report['events'].append({'phase': label, 'pid': child.pid, 'health': health})
            return child, health
        child, health = start('initial')
        session = request_http('/api/session/new', {'workspace': str(root / 'home'), 'model': 'rehearsal-model', 'model_provider': 'custom'})
        (root / 'session-created.json').write_text(json.dumps(session))
        sid = session.get('session_id') or session.get('session', {}).get('session_id')
        canary.require(sid, 'No session id: ' + repr(session))
        result = request_http('/api/chat/start', {'session_id': sid, 'message': 'INITIAL_PROCESS_MARKER', 'workspace': str(root / 'home'), 'model': 'rehearsal-model', 'model_provider': 'custom'})
        (root / 'initial-chat.json').write_text(json.dumps(result))
        def messages():
            with sqlite3.connect('file:' + str(root / 'state/state.db') + '?mode=ro', uri=True) as db:
                return db.execute('SELECT role, content FROM messages WHERE session_id=? ORDER BY id', (sid,)).fetchall()
        def settled(count):
            rows = messages()
            sidecar = json.loads((root / 'webui/sessions' / (sid + '.json')).read_text())
            return rows if sum(role == 'assistant' and text == 'REHEARSAL_RESPONSE_OK' for role, text in rows) == count and not sidecar.get('active_stream_id') and not sidecar.get('pending_user_message') else None
        wait(lambda: settled(1), 'initial real inference', 60)
        def idle_health():
            value = request_http('/health?deep=1')
            return value if value.get('active_runs') == 0 and value.get('active_streams') == 0 else None
        health = wait(idle_health, 'settled health'); (root / 'health.json').write_text(json.dumps(health))
        def snapshot(label):
            with sqlite3.connect('file:' + str(root / 'state/state.db') + '?mode=ro', uri=True) as db:
                db.row_factory = sqlite3.Row
                value = {'sidecar': json.loads((root / 'webui/sessions' / (sid + '.json')).read_text()),
                         'row': dict(db.execute('SELECT * FROM sessions WHERE id=?', (sid,)).fetchone()),
                         'messages': [dict(r) for r in db.execute('SELECT * FROM messages WHERE session_id=? ORDER BY id', (sid,))]}
            (root / ('binding-' + label + '.json')).write_text(json.dumps(value, indent=2, default=lambda v: bytes(v).hex()))
        publish('request', sid)
        snapshot('published')
        canary.stop(child)
        snapshot('exited')
        report['events'].append({'phase': 'initial_exit', 'pid': child.pid, 'returncode': child.returncode})
        child, health = start('relaunch')
        snapshot('relaunch')
        (root / 'health.json').write_text(json.dumps(health))
        publish('terminal', str(child.pid))
        rows = wait(lambda: settled(2), 'continuation real inference', 60)
        private = root / 'private'
        for suffix in ('claim', 'entered', 'result'):
            report[suffix] = json.loads((private / ('a' * 32 + '.' + suffix + '.json')).read_text())
        canary.require(report['entered']['stream_id'] == report['result']['stream_id'], 'Receipt mismatch')
        before = list(rows)
        canary.stop(child)
        child, health = start('duplicate_relaunch')
        time.sleep(3)
        canary.require(messages() == before, 'Duplicate replay changed transcript')
        duplicate_events = [json.loads(line) for line in (root / 'duplicate_relaunch-consumer.jsonl').read_text().splitlines()]
        canary.require(any(e.get('result', {}).get('status') == 'already_claimed' for e in duplicate_events), 'Duplicate consumer did not attest already_claimed')
        canary.require(sum(role == 'user' and text == 'CONTINUATION_PROCESS_MARKER' for role, text in before) == 1, 'Continuation not exactly once')
        report.update(status='passed', session_id=sid, transcript=rows, inference_requests=len(requests))
    except BaseException as e:
        report['error'] = repr(e)
        raise
    finally:
        errors = []
        for child in reversed(processes):
            try: canary.stop(child)
            except Exception as e: errors.append(str(e))
        for log in logs: log.close()
        if fake: fake.shutdown(); fake.server_close()
        report['cleanup_errors'] = errors
        if errors: report['status'] = 'failed'
        (root / 'report.json').write_text(json.dumps(report, indent=2))
        print('REPORT=' + str(root / 'report.json'), flush=True)


if __name__ == '__main__':
    run()
