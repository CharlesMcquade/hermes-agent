"""Build an isolated signed controller lab; never install/launch production jobs."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import socket
import subprocess
import sys

SOURCE = Path(__file__).resolve().parent
CONTROL = SOURCE.parents[1] / "scripts/production_control"
sys.path.insert(0, str(CONTROL))
from production_launcher import inventory  # noqa: E402
from restart_production import ASSETS  # noqa: E402

BUNDLE_ID = "com.charles.verity.controllerlab"
FIXTURE = """# Synthetic lifecycle fixture: no Hermes imports, credentials, or messaging.
import http.server,json,os,pathlib,signal,subprocess,sys,time
role=sys.argv[1]
base=pathlib.Path(os.environ['TEST_BASE'])
started=time.time()
worker=subprocess.Popen([sys.executable,'-I','-c',
    'import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(600)'])
with (base/'state'/'processes.jsonl').open('a') as f:
 f.write(json.dumps({'role':role,'pid':os.getpid(),'ppid':os.getppid(),'pgid':os.getpgrp(),
    'worker':worker.pid,'started':started})+'\\n')
if role=='agent':
 p=base/'state'/'gateway_state.json'
 p.write_text(json.dumps({'pid':os.getpid(),'gateway_state':'running',
    'code_sha':os.environ['TEST_SHA'],'updated_at':started}))
 while True: time.sleep(1)
class H(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  if self.path.startswith('/health'):
   bad=(base/'shallow-failure').exists() or ((base/'deep-failure').exists() and 'deep=1' in self.path)
   data=json.dumps({'status':'error' if bad else 'ok','server_started_at':started}).encode()
  elif self.path.startswith('/static/'):
   name=self.path[len('/static/'):]
   if '/' in name or name not in os.environ['TEST_ASSETS'].split(','): self.send_error(404);return
   data=(pathlib.Path.cwd()/'static'/name).read_bytes()
  else: self.send_error(404);return
  self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
 def log_message(self,*args): pass
http.server.ThreadingHTTPServer(('127.0.0.1',int(os.environ['TEST_PORT'])),H).serve_forever()
"""


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise RuntimeError(f"{Path(args[0]).name} failed: {result.stderr}")
    return result


def build(root, identity_path):
    # Each invocation gets a fresh retained root; never replace a running artifact.
    root = root.absolute()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    identity = json.loads(identity_path.read_text())
    pin = identity["sha1"]
    if not re.fullmatch("[a-fA-F0-9]{40}", pin):
        raise ValueError("Invalid public signer fingerprint")
    for name in ("home", "tmp", "state", "agent", "webui"):
        (root / name).mkdir(mode=0o700)
    bootstrap = sys.executable
    shutil.copyfile(CONTROL / "production_launcher.py", root / "production_launcher.py")
    app = root / "Verity Controller Lab.app"
    binary = app / "Contents/MacOS/VerityServiceHost"
    resources = app / "Contents/Resources"
    binary.parent.mkdir(parents=True)
    resources.mkdir()
    config = {
        "base": str(root),
        "bootstrap_python": bootstrap,
        "launcher": str(root / "production_launcher.py"),
        "launcher_sha256": digest(root / "production_launcher.py"),
        "roles": ["agent", "webui"],
    }
    (resources / "service-settings.json").write_text(
        json.dumps(config, indent=2) + "\n"
    )
    (app / "Contents/Info.plist").write_bytes(
        plistlib.dumps({
            "CFBundleIdentifier": BUNDLE_ID,
            "CFBundleName": "Verity Controller Lab",
            "CFBundleExecutable": binary.name,
            "CFBundleVersion": "1",
            "CFBundlePackageType": "APPL",
            "LSUIElement": True,
            "LSMinimumSystemVersion": "14.0",
        })
    )
    run([
        "xcrun",
        "swiftc",
        "-target",
        "arm64-apple-macos14.0",
        "-swift-version",
        "5",
        str(SOURCE / "ServiceHost.swift"),
        "-o",
        str(binary),
    ])
    requirement = f'identifier "{BUNDLE_ID}" and certificate leaf = H"{pin.lower()}"'
    req = root / "requirements.txt"
    req.write_text("designated => " + requirement + "\n")
    run([
        "/usr/bin/codesign",
        "--force",
        "--sign",
        pin,
        "--keychain",
        identity["keychain"],
        "--timestamp=none",
        "--requirements",
        str(req),
        str(app),
    ])
    run([
        "/usr/bin/codesign",
        "--verify",
        "--strict",
        "-R",
        "=" + requirement,
        str(app),
    ])
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    labels = {
        s: f"com.charles.verity.controllerlab.{os.getpid()}.{s}"
        for s in config["roles"]
    }
    manifest = {
        "schema_version": 2,
        "release_id": "synthetic-controller-lab",
        "labels": labels,
        "state_dir": str(root / "state"),
        "services": {},
        "health_url": f"http://127.0.0.1:{port}/health",
        "native_host": {
            "bundle": str(app),
            "executable": str(binary),
            "bundle_id": BUNDLE_ID,
            "requirement": requirement,
            "inventory": inventory(app),
            "launcher_sha256": config["launcher_sha256"],
        },
    }
    for role in config["roles"]:
        repo = root / role
        (repo / "main.py").write_text(FIXTURE)
        if role == "webui":
            (repo / "static").mkdir()
            for name in ASSETS:
                (repo / "static" / name).write_text("synthetic controller lab asset\n")
        plist = root / (role + ".plist")
        definition = {
            "Label": labels[role],
            "ProgramArguments": [str(binary), role],
            "WorkingDirectory": str(root),
            "RunAtLoad": True,
            "KeepAlive": True,
            "AssociatedBundleIdentifiers": [BUNDLE_ID],
            "ThrottleInterval": 1,
            "AbandonProcessGroup": False,
            "StandardOutPath": str(root / (role + ".out")),
            "StandardErrorPath": str(root / (role + ".err")),
        }
        plist.write_bytes(plistlib.dumps(definition))
        manifest["services"][role] = {
            "repo": str(repo),
            "cwd": str(repo),
            "commit": "fixture-old",
            "argv": [bootstrap, "-I", "-B", str(repo / "main.py"), role],
            "inventory": inventory(repo),
            "plist_path": str(plist),
            "env": {
                "TEST_BASE": str(root),
                "TEST_PORT": str(port),
                "TEST_SHA": "fixture-old",
                "TEST_ASSETS": ",".join(ASSETS),
            },
        }
    (root / "production-release.json").write_text(json.dumps(manifest, indent=2) + "\n")
    report = {
        "root": str(root),
        "labels": labels,
        "binary_sha256": digest(binary),
        "source_sha256": digest(SOURCE / "ServiceHost.swift"),
        "requirement": requirement,
        "synthetic_services": True,
        "installed": False,
    }
    (root / "build-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return root


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--identity", required=True, type=Path)
    args = parser.parse_args()
    build(args.root, args.identity)
