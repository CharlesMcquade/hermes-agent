"""Disposable native topology/recovery gate, NOT a refresh publication gate.

Build is filesystem-only. Review build-report.json, then pass its SHA256 with
--live --build-sha256. Only that opt-in signs/launches. Uses retained machine
code, synthetic services, and the existing independent launchd controller recipe.
Refresh publication/schema fences/exact-return remain separate fixture gates.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import struct
import sys

SCRATCH = Path('/Users/charles/.hermes/cache/scratch')
SOURCE = SCRATCH / 'verity-refresh-parent-9p6fk_g_/source-v4'
HOST = Path('/Users/charles/.hermes/experiments/verity-production-stage-v1/Verity.app/Contents/MacOS/VerityServiceHost')
PIN = 'B72A53676319B035EF637A6DEF27F026009D989C'
# Explicit lookup retains isolated HOME; no keychain export or trust mutation.
KEYCHAIN = Path('/Users/charles/Library/Keychains/login.keychain-db')
BUNDLE = 'com.charles.verity.controllerlab'
FILES = ('production_launcher.py', 'restart_production.py', 'watchdog.py',
         'approved_restart_job.py', 'native_identity.py', 'control_refresh.py')
ROLES = ('agent', 'webui')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(data):
    return (json.dumps(data, sort_keys=True, indent=2) + '\n').encode()


def root_path(root, *, new=False):
    root = Path(root)
    require(root.is_absolute() and root == root.resolve() and root.parent == SCRATCH.resolve()
            and re.fullmatch(r'verity-control-live-[0-9a-f]{32}', root.name), 'Unsafe lab root')
    st = root.parent.stat()
    require(st.st_uid == os.getuid() and not st.st_mode & 0o022, 'Unsafe scratch parent')
    require(not new or not root.exists(), 'Root must be new')
    if root.exists():
        st = root.stat()
        require(st.st_uid == os.getuid() and st.st_mode & 0o777 == 0o700, 'Lab must be private')
    return root


def contained(root, path):
    path = Path(path)
    require(path.is_absolute() and path == path.resolve() and path.is_relative_to(root),
            'Path escapes lab or is a symlink')
    return path


def env(root):
    return dict(HOME=str(root / 'home'), TMPDIR=str(root / 'tmp'), HERMES_HOME=str(root / 'state'),
                PATH='/usr/bin:/bin:/usr/sbin:/sbin', PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1')


def helpers():
    # Only the reviewed snapshot, never application modules or the mutable checkout.
    for path in (SOURCE / 'scripts/production_control', SOURCE / 'experiments/verity_identity'):
        sys.path.insert(0, str(path))
    import build_controller_lab as b
    import verify_native_migration_live as m
    import restart_production as c
    for module in (b, m, c):
        require(Path(module.__file__).resolve().is_relative_to(SOURCE), 'Unexpected imported helper')
    return b, m, c


def machine_code(data):
    """Hash every executable Mach-O segment; signing may change LINKEDIT only."""
    require(len(data) >= 32 and data[:4] == b'\xcf\xfa\xed\xfe', 'Expected thin little-endian Mach-O64')
    ncmds, size = struct.unpack_from('<II', data, 16)
    require(32 + size <= len(data), 'Truncated Mach-O')
    offset, segments = 32, []
    for _ in range(ncmds):
        cmd, length = struct.unpack_from('<II', data, offset)
        require(length >= 8 and offset + length <= 32 + size, 'Invalid load command')
        if cmd == 0x19:
            require(length >= 72, 'Truncated segment')
            fileoff, filesize = struct.unpack_from('<QQ', data, offset + 40)
            initprot = struct.unpack_from('<I', data, offset + 60)[0]
            if initprot & 4:
                # Header/load commands change with signing. Hash executable sections.
                nsects = struct.unpack_from('<I', data, offset + 64)[0]
                require(72 + 80 * nsects <= length, 'Invalid section count')
                for i in range(nsects):
                    section = offset + 72 + i * 80
                    length_s = struct.unpack_from('<Q', data, section + 40)[0]
                    start = struct.unpack_from('<I', data, section + 48)[0]
                    require(start + length_s <= len(data), 'Truncated section')
                    segments.append(data[start:start + length_s])
        offset += length
    require(segments, 'No executable sections')
    return digest(b''.join(segments))


def build(root, port):
    root = root_path(root, new=True)
    require(type(port) is int and 1024 <= port <= 65535, 'Explicit unprivileged loopback port required')
    require(HOST == HOST.resolve() and HOST.is_file(), 'Retained host missing or symlinked')
    host_bytes = HOST.read_bytes()
    code_hash = machine_code(host_bytes)
    b, _, _ = helpers()
    python = sys.executable
    root.mkdir(mode=0o700)
    def put(name, data):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    for name in ('home', 'tmp', 'state', 'agent', 'webui', 'control'):
        (root / name).mkdir(mode=0o700)
    for name in FILES:
        put('control/' + name, (SOURCE / 'scripts/production_control' / name).read_bytes())
        (root / 'control' / name).chmod(0o444)
    (root / 'control').chmod(0o555)
    launcher = (root / 'control/production_launcher.py').read_text()
    put('production_launcher.py', launcher.encode())
    app = root / 'Verity Controller Lab.app'
    binary = app / 'Contents/MacOS/VerityServiceHost'
    put(str(binary.relative_to(root)), host_bytes)
    binary.chmod(0o755)
    require(binary.read_bytes() == host_bytes, 'Pre-sign copy differs')
    settings = dict(base=str(root), bootstrap_python=python, launcher=str(root / 'production_launcher.py'),
                    launcher_sha256=digest(launcher.encode()), roles=list(ROLES), bootstrap_environment=env(root))
    put(str((app / 'Contents/Resources/service-settings.json').relative_to(root)), encoded(settings))
    put(str((app / 'Contents/Info.plist').relative_to(root)), plistlib.dumps(dict(
        CFBundleIdentifier=BUNDLE, CFBundleName='Verity Controller Lab', CFBundleExecutable=binary.name,
        CFBundleVersion='1', CFBundlePackageType='APPL', LSUIElement=True, LSMinimumSystemVersion='14.0')))
    # The approved hostile-worker fixture remains responsible for lifetime receipts.
    put('agent/hermes_cli/__init__.py', b'')
    gateway = b.FIXTURE.replace('role=sys.argv[1]', "assert sys.argv[1:]==['gateway','run','--external-supervisor']\nrole='agent'")
    put('agent/hermes_cli/main.py', gateway.encode())
    wrapper = ("import os,signal,subprocess,sys\n"
               "assert sys.argv[1]=='--error-log' and sys.argv[3]=='--'\n"
               "child=subprocess.Popen(sys.argv[4:])\n"
               "signal.signal(signal.SIGTERM,lambda *_:child.terminate())\n"
               "signal.signal(signal.SIGINT,lambda *_:child.terminate())\n"
               "raise SystemExit(child.wait())\n")
    put('agent/hermes_cli/stderr_timestamp.py', wrapper.encode())
    put('webui/main.py', b.FIXTURE.encode())
    for name in b.ASSETS:
        put('webui/static/' + name, b'synthetic lab asset\n')
    labels = {r: f'{BUNDLE}.{int(root.name[-32:], 16)}.{r}' for r in ROLES}
    manifest = dict(schema_version=2, release_id='synthetic-timestamp-native', labels=labels,
                    state_dir=str(root / 'state'), health_url=f'http://127.0.0.1:{port}/health', services={},
                    native_host=dict(bundle=str(app), executable=str(binary), bundle_id=BUNDLE,
                        requirement=f'identifier "{BUNDLE}" and certificate leaf = H"{PIN.lower()}"',
                        inventory=b.inventory(app), launcher_sha256=settings['launcher_sha256']))
    for role in ROLES:
        repo = root / role
        argv = ([python, '-m', 'hermes_cli.stderr_timestamp', '--error-log', str(root / 'state/gateway.err'),
                 '--', python, '-m', 'hermes_cli.main', 'gateway', 'run', '--external-supervisor']
                if role == 'agent' else [python, '-I', '-B', str(repo / 'main.py'), role])
        service_env = dict(env(root), TEST_BASE=str(root), TEST_PORT=str(port), TEST_SHA='fixture-old',
                           TEST_ASSETS=','.join(b.ASSETS))
        if role == 'agent':
            service_env['PYTHONPATH'] = str(repo)
        manifest['services'][role] = dict(repo=str(repo), cwd=str(repo), commit='fixture-old', argv=argv,
            inventory=b.inventory(repo), plist_path=str(root / (role + '.plist')), env=service_env)
        definition = dict(Label=labels[role], ProgramArguments=[str(binary), role], WorkingDirectory=str(root),
            RunAtLoad=True, KeepAlive=True, AssociatedBundleIdentifiers=[BUNDLE], ThrottleInterval=1,
            AbandonProcessGroup=False, StandardOutPath=str(root / (role + '.out')),
            StandardErrorPath=str(root / (role + '.err')))
        put(role + '.plist', plistlib.dumps(definition))
    put('production-release.json', encoded(manifest))
    # Reuse the existing independent job verbatim. Its operation imports sealed controls.
    scrub = ('import os\nos.environ.clear()\n' + f'os.environ.update({env(root)!r})\n').encode()
    put('verify_controller_live.py', scrub + (SOURCE / 'experiments/verity_identity/verify_controller_live.py').read_bytes())
    put('verify_service_host_live.py', (SOURCE / 'experiments/verity_identity/verify_service_host_live.py').read_bytes())
    # Helper inserts its inferred CONTROL first; root-local modules are the sealed copies.
    for name in FILES:
        put(name, (root / 'control' / name).read_bytes()) if name != 'production_launcher.py' else None
        if name != 'production_launcher.py':
            (root / name).chmod(0o444)
    (root / 'production_launcher.py').chmod(0o444)
    settings['launcher_sha256'] = digest((root / 'production_launcher.py').read_bytes())
    put(str((app / 'Contents/Resources/service-settings.json').relative_to(root)), encoded(settings))
    manifest['native_host'].update(launcher_sha256=settings['launcher_sha256'], inventory=b.inventory(app))
    put('production-release.json', encoded(manifest))
    report = dict(root=str(root), labels=labels, synthetic_services=True, installed=False,
                  source=str(SOURCE), python=python, retained_host=str(HOST), presign_sha256=digest(host_bytes),
                  machine_code_sha256=code_hash, port=port,
                  scope='native topology/readiness/bounded rollback only; refresh publication and exact return are separate fixture gates',
                  files={str(p.relative_to(root)): digest(p.read_bytes()) for p in root.rglob('*') if p.is_file()})
    put('build-report.json', encoded(report))
    return dict(root=str(root), build_sha256=digest(encoded(report)), live_executed=False)


def preflight(root, pin):
    root = root_path(root)
    require(isinstance(pin, str) and re.fullmatch('[0-9a-f]{64}', pin), 'Explicit build SHA256 required')
    raw = contained(root, root / 'build-report.json').read_bytes()
    require(digest(raw) == pin, 'Build receipt mismatch')
    report = json.loads(raw)
    require(report['root'] == str(root) and report['source'] == str(SOURCE)
            and report['retained_host'] == str(HOST) and report['python'] == sys.executable, 'Foreign build')
    require(report['synthetic_services'] is True and report['installed'] is False, 'Not a synthetic build')
    for name, expected in report['files'].items():
        path = contained(root, root / name)
        st = path.stat()
        require(st.st_uid == os.getuid() and not st.st_mode & 0o022, 'Unsafe artifact ownership/mode')
        if name in FILES or name.startswith('control/'):
            require(st.st_mode & 0o777 == 0o444, 'Controls must stay sealed')
        require(digest(path.read_bytes()) == expected, 'Build artifact drift: ' + name)
    require((root / 'control').stat().st_mode & 0o777 == 0o555, 'Control directory must stay sealed')
    # Reject extra importable code and symlinks before any helper/native operation.
    actual = {str(p.relative_to(root)) for p in root.rglob('*') if p.is_file() or p.is_symlink()}
    require(actual == set(report['files']) | {'build-report.json'}, 'Unexpected lab files')
    return report


def live(root, pin, *, approved=False):
    require(approved, 'Explicit --live approval required')
    report = preflight(root, pin)
    root = Path(root)
    import subprocess
    import time
    b, migration, control = helpers()
    from verify_service_host_live import launchctl, until, set_cleanup_outcome
    app = root / 'Verity Controller Lab.app'
    binary = app / 'Contents/MacOS/VerityServiceHost'
    proof = dict(status='running', scope=report['scope'], cases=[], build_sha256=pin)
    targets = []
    original_env = os.environ.copy()
    os.environ.clear()
    os.environ.update(env(root))
    try:
        def run(argv):
            return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=120, env=env(root))
        # The copied binary still matches the retained bytes at preflight. The new
        # bundle's settings intentionally differ, so its old resource signature
        # cannot validate here; verify the newly signed bundle strictly below.
        requirement = f'identifier "{BUNDLE}" and certificate leaf = H"{PIN.lower()}"'
        (root / 'requirements.txt').write_text('designated => ' + requirement + '\n')
        run(['/usr/bin/codesign', '--force', '--sign', PIN, '--keychain', str(KEYCHAIN),
             '--timestamp=none', '--requirements', str(root / 'requirements.txt'), str(app)])
        run(['/usr/bin/codesign', '--verify', '--strict', '-R', '=' + requirement, str(app)])
        require(machine_code(binary.read_bytes()) == report['machine_code_sha256'], 'Machine code changed')
        manifest = json.loads((root / 'production-release.json').read_bytes())
        manifest['native_host']['inventory'] = b.inventory(app)
        original = encoded(manifest)
        (root / 'production-release.json').write_bytes(original)
        saved = {r: (root / (r + '.plist')).read_bytes() for r in ROLES}
        c = control.Controller(root, timeout=12, stable_seconds=1)
        c.preflight(manifest)
        def snapshot():
            snap = c.wait_ready(manifest, c.definitions(manifest), since=None, previous=None)
            identities = snap['process_identity']
            require('wrapper' in identities['agent'] and 'wrapper' not in identities['webui'], 'Incorrect topology')
            return snap
        for role in ROLES:
            target = c.target(manifest, role)
            require(launchctl('print', target, check=False).returncode == 113, 'Label is not absent')
            targets.append(target)
            launchctl('bootstrap', f'gui/{os.getuid()}', str(root / (role + '.plist')))
        proof['cases'].append(dict(name='timestamp_wrapper_direct_webui', snapshot=snapshot()))
        before = migration.evidence(root)
        # Existing independent() uses its own __file__. Execute a root-local copy
        # so the launchd-owned operation imports exactly the captured controls.
        import importlib.util
        spec = importlib.util.spec_from_file_location('_isolated_controller_gate', root / 'verify_controller_live.py')
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        result = gate.independent(root, 'restart')
        require(result['status'] == 'verified', 'Independent restart failed: ' + str(result))
        until(lambda: migration.gone(before))
        proof['cases'].append(dict(name='independent_restart', result=result, snapshot=snapshot()))
        bad = copy.deepcopy(manifest)
        broken = root / 'broken-webui'
        shutil.copytree(root / 'webui', broken)
        (broken / 'main.py').write_text('raise SystemExit(9)\n')
        bad['release_id'] = 'synthetic-failed-start'
        bad['services']['webui'].update(repo=str(broken), cwd=str(broken), inventory=b.inventory(broken),
            argv=[sys.executable, '-I', '-B', str(broken / 'main.py'), 'webui'])
        candidate = root / 'bad-native.json'
        candidate.write_bytes(encoded(bad))
        c.preflight(bad)
        before = migration.evidence(root)
        started = time.monotonic()
        result = gate.independent(root, 'restart', candidate=str(candidate))
        require(result['status'] == 'rolled_back' and time.monotonic() - started < 90, 'Bounded rollback failed')
        require((root / 'production-release.json').read_bytes() == original and all(
            (root / (r + '.plist')).read_bytes() == saved[r] for r in ROLES), 'Rollback bytes differ')
        until(lambda: migration.gone(before))
        proof['cases'].append(dict(name='bounded_exact_rollback', result=result, snapshot=snapshot()))
    except BaseException as exc:
        proof.update(status='failed', error=str(exc), error_type=type(exc).__name__)
        raise
    finally:
        errors = []
        # independent helper has a finally bootout; retry its known label here.
        if targets:
            targets.append(f'gui/{os.getuid()}/{BUNDLE}.{os.getpid()}.controller')
        for target in reversed(targets):
            try:
                launchctl('bootout', '--wait', target, check=False)
                require(launchctl('print', target, check=False).returncode == 113, 'Label remains loaded')
            except Exception as exc:
                errors.append(str(exc))
        try:
            if targets:
                until(lambda: migration.gone(migration.evidence(root)))
        except Exception as exc:
            errors.append(str(exc))
        set_cleanup_outcome(proof, errors, targets)
        proof['status'] = 'failed' if errors or proof['status'] == 'failed' else 'passed'
        (root / 'native-live-report.json').write_bytes(encoded(proof))
        os.environ.clear()
        os.environ.update(original_env)
        if errors:
            raise RuntimeError(errors)
    return proof


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--port', type=int)
    p.add_argument('--build-sha256')
    p.add_argument('--live', action='store_true')
    args = p.parse_args()
    if args.live:
        require(args.port is None, '--port belongs to build only')
        import signal
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
        result = live(args.root, args.build_sha256, approved=True)
    elif args.build_sha256:
        result = preflight(args.root, args.build_sha256)
    else:
        result = build(args.root, args.port)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
