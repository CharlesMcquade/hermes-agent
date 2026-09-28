"""Opt-in synthetic legacy -> native migration. Never install production artifacts."""
import argparse
import copy
import json
import os
from pathlib import Path
import plistlib
import re
import signal
import socket
import subprocess
import sys
import time

SOURCE = Path(__file__).resolve().parent
sys.path.insert(0, str(SOURCE))
from build_controller_lab import BUNDLE_ID, FIXTURE as HOST_FIXTURE, CONTROL, ASSETS
from stage_production_native import FILES, compile_host, encoded, put, wrappers, digest
from verify_service_host_live import launchctl, until, alive, current, set_cleanup_outcome
from production_launcher import inventory
from restart_production import Controller
from native_identity import bootstrap_environment

ROLES = ("agent", "webui")
# The legacy synthetic supervisor must reap its own intentionally hostile worker.
# Native children keep the original TERM-ignoring workers and rely on host/guard.
# This does NOT claim arbitrary legacy production descendants are cleanup-safe.
FIXTURE = HOST_FIXTURE.replace(
    "with (base/'state'/'processes.jsonl').open('a') as f:",
    """if os.getppid()==1:
 def legacy_stop(sig,frame):
  worker.kill();worker.wait(timeout=5);raise SystemExit(128+sig)
 signal.signal(signal.SIGTERM,legacy_stop)
 signal.signal(signal.SIGINT,legacy_stop)
with (base/'state'/'processes.jsonl').open('a') as f:""",
)
# This is deliberately a local lab recipe, not a configurable installation API.
SCRATCH = Path("/Users/charles/.hermes/cache/scratch")
IDENTITY = Path("/Users/charles/.hermes/signing/verity-lab-v3/identity.json")


def require(value, message):
    if not value:
        raise ValueError(message)


def new_root(root):
    root = Path(root)
    require(root.is_absolute() and root == root.resolve(), "Noncanonical root")
    require(root.parent == SCRATCH.resolve() and re.fullmatch(
        r"verity-migration-[0-9a-f]{32}", root.name), "Use a unique lab scratch root")
    require(not root.exists(), "Root must be NEW")
    st = root.parent.stat()
    require(st.st_uid == os.getuid() and not st.st_mode & 0o022,
            "Scratch parent must be privately controlled")
    return root


def contained(root, path):
    path = Path(path)
    require(path.is_absolute() and path == path.resolve() and path.is_relative_to(root),
            "Path escapes private lab root")
    return path


def environment(root):
    return bootstrap_environment({"base": str(root), "bootstrap_environment": {
        "HOME": str(root / "home"), "TMPDIR": str(root / "tmp"),
        "HERMES_HOME": str(root / "state"), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"}})


def legacy_definition(root, role, python):
    return dict(Label=f"{BUNDLE_ID}.migration.{root.name[-32:]}.{role}",
                Program=python,
                ProgramArguments=[python, str(root / "production_launcher.py"), role],
                WorkingDirectory=str(root), RunAtLoad=True, KeepAlive=True,
                ThrottleInterval=1, AbandonProcessGroup=False,
                EnvironmentVariables=environment(root),
                StandardOutPath=str(root / (role + ".out")),
                StandardErrorPath=str(root / (role + ".err")))


def validate_inputs(root, manifest, plists, python):
    """Strict synthetic boundary, before controller preflight/import probes or writes."""
    require(root == root.resolve() and root.parent == SCRATCH.resolve() and
            re.fullmatch(r"verity-migration-[0-9a-f]{32}", root.name), "Unsafe root")
    if root.exists():
        st = root.stat()
        require(st.st_uid == os.getuid() and st.st_mode & 0o777 == 0o700, 'Lab root must stay private')
    require(set(manifest) == {"schema_version", "release_id", "labels", "state_dir",
                             "services", "health_url"}, "Not a legacy synthetic manifest")
    require(manifest['schema_version'] == 2 and manifest['release_id'] == 'synthetic-legacy',
            'Unexpected synthetic release')
    require(manifest['state_dir'] == str(root / 'state'), 'External state')
    require(set(manifest['services']) == set(ROLES) and set(manifest['labels']) == set(ROLES),
            'Unexpected roles')
    require(re.fullmatch(r'http://127\.0\.0\.1:[0-9]+/health', manifest['health_url']),
            'Only synthetic loopback health is permitted')
    port = manifest['health_url'].split(':')[2].split('/')[0]
    require(0 < int(port) < 65536, 'Invalid port')
    for role in ROLES:
        definition = legacy_definition(root, role, python)
        require(plistlib.loads(plists[role]) == definition, 'Unsafe legacy plist')
        require(manifest['labels'][role] == definition['Label'], 'Unsafe label')
        item = manifest['services'][role]
        repo = contained(root, root / role)
        require(set(item) == {'repo', 'cwd', 'commit', 'argv', 'inventory', 'plist_path', 'env'},
                'Unexpected service fields (no probes, credentials or env files)')
        require(item['repo'] == item['cwd'] == str(repo) and
                item['plist_path'] == str(root / (role + '.plist')) and
                item['argv'] == [python, '-I', '-B', str(repo / 'main.py'), role] and
                item['commit'] == 'fixture-old', 'Non-synthetic service paths/argv')
        require(item['env'] == dict(environment(root), TEST_BASE=str(root), TEST_PORT=port,
                                   TEST_SHA='fixture-old', TEST_ASSETS=','.join(ASSETS)),
                'Non-synthetic service environment')
        for path in (repo, root / (role + '.plist'), root / 'state', root / 'home',
                     root / 'tmp', root / (role + '.out'), root / (role + '.err')):
            contained(root, path)
        require((repo / 'main.py').read_text() == FIXTURE and inventory(repo) == item['inventory'],
                'Not the approved synthetic fixture')


def build(root, identity=IDENTITY, *, live=False, runner=None):
    require(live, 'Explicit --live-synthetic approval required')
    root = new_root(root)  # All caller-controlled inputs checked before mkdir/signing.
    require(Path(identity) == IDENTITY and IDENTITY.resolve() == IDENTITY,
            'Only the existing approved lab identity is allowed')
    signer = json.loads(IDENTITY.read_text(encoding="utf-8"))
    require(re.fullmatch(r'[0-9a-fA-F]{40}', signer['sha1']), 'Invalid lab fingerprint')
    require(signer.get('purpose') != 'production', 'Production signer forbidden')
    python = sys.executable
    require(Path(python).is_absolute() and os.access(python, os.X_OK), 'Invalid Python')
    root.mkdir(mode=0o700)
    for name in ('home', 'tmp', 'state', *ROLES):
        (root / name).mkdir(mode=0o700)
    for name in FILES:
        put(root / 'control' / name, (CONTROL / name).read_bytes())
    for name, text in wrappers(root, root / 'control').items():
        if name == 'production_launcher.py':
            # launchd EnvironmentVariables augments its inherited environment.
            # Scrub that inheritance for the legacy path too, before launcher import.
            text = ('import os\nos.environ.clear()\n'
                    f'os.environ.update({environment(root)!r})\n') + text
        put(root / name, text.encode())
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    old = dict(schema_version=2, release_id='synthetic-legacy', labels={}, services={},
               state_dir=str(root / 'state'), health_url=f'http://127.0.0.1:{port}/health')
    saved = {}
    for role in ROLES:
        repo = root / role
        put(repo / 'main.py', FIXTURE.encode())
        if role == 'webui':
            for name in ASSETS:
                put(repo / 'static' / name, b'synthetic migration asset\n')
        definition = legacy_definition(root, role, python)
        saved[role] = plistlib.dumps(definition)
        old['labels'][role] = definition['Label']
        old['services'][role] = dict(repo=str(repo), cwd=str(repo), commit='fixture-old',
            argv=[python, '-I', '-B', str(repo / 'main.py'), role], inventory=inventory(repo),
            plist_path=str(root / (role + '.plist')), env=dict(environment(root),
            TEST_BASE=str(root), TEST_PORT=str(port), TEST_SHA='fixture-old', TEST_ASSETS=','.join(ASSETS)))
    validate_inputs(root, old, saved, python)
    for role in ROLES:
        put(root / (role + '.plist'), saved[role])
        put(root / 'saved' / (role + '.plist'), saved[role])
    put(root / 'production-release.json', encoded(old))
    put(root / 'saved/legacy.json', encoded(old))
    app = root / 'Verity Controller Lab.app'
    binary = app / 'Contents/MacOS/VerityServiceHost'
    binary.parent.mkdir(parents=True)
    launcher_hash = digest((root / 'production_launcher.py').read_bytes())
    put(app / 'Contents/Resources/service-settings.json', encoded(dict(base=str(root),
        bootstrap_python=python, launcher=str(root / 'production_launcher.py'),
        launcher_sha256=launcher_hash, roles=list(ROLES), bootstrap_environment=environment(root))))
    put(app / 'Contents/Info.plist', plistlib.dumps(dict(CFBundleIdentifier=BUNDLE_ID,
        CFBundleName='Verity Controller Lab', CFBundleExecutable=binary.name,
        CFBundleVersion='1', CFBundlePackageType='APPL', LSUIElement=True,
        LSMinimumSystemVersion='14.0')))
    put(root / 'ServiceHost.swift', (SOURCE / 'ServiceHost.swift').read_bytes())
    def run(argv, *, env=None):
        subprocess.run(argv, env=env or environment(root), check=True,
                       capture_output=True, timeout=120)
    runner = runner or run
    compile_host(root, root / 'ServiceHost.swift', binary, runner=runner)
    requirement = f'identifier "{BUNDLE_ID}" and certificate leaf = H"{signer["sha1"].lower()}"'
    put(root / 'requirements.txt', ('designated => ' + requirement + '\n').encode())
    runner(['/usr/bin/codesign', '--force', '--sign', signer['sha1'], '--keychain',
            signer['keychain'], '--timestamp=none', '--requirements', str(root / 'requirements.txt'), str(app)])
    runner(['/usr/bin/codesign', '--verify', '--strict', '-R', '=' + requirement, str(app)])
    native = copy.deepcopy(old)
    native.update(release_id='synthetic-native', native_host=dict(bundle=str(app),
        executable=str(binary), bundle_id=BUNDLE_ID, requirement=requirement,
        inventory=inventory(app), launcher_sha256=launcher_hash), launchd_overrides={})
    for role in ROLES:
        native['launchd_overrides'][role] = dict(ProgramArguments=[str(binary), role],
            WorkingDirectory=str(root), AssociatedBundleIdentifiers=[BUNDLE_ID], AbandonProcessGroup=False)
    bad = copy.deepcopy(native)
    broken = root / 'broken-webui'
    put(broken / 'main.py', FIXTURE.replace("if (base/'startup-block').exists():", 'if True:').encode())
    for name in ASSETS:
        put(broken / 'static' / name, (root / 'webui/static' / name).read_bytes())
    bad['release_id'] = 'synthetic-native-failed-start'
    bad['services']['webui'].update(repo=str(broken), cwd=str(broken), inventory=inventory(broken),
        argv=[python, '-I', '-B', str(broken / 'main.py'), 'webui'])
    put(root / 'native.json', encoded(native))
    put(root / 'bad-native.json', encoded(bad))
    # Independent controller imports the captured native-aware control, never applications.
    script = (f'import sys,json,os\nfrom pathlib import Path\nsys.path.insert(0,{str(root / "control")!r})\n'
              'from restart_production import Controller,save_json\n'
              'assert os.getppid()==1\n'
              f'c=Controller(Path({str(root)!r}),timeout=12,stable_seconds=1)\n'
              'try:\n r=c.restart(candidate=sys.argv[2] if len(sys.argv)>2 else None,reload=True,yes=True)\n'
              "except Exception as e:\n r=dict(status='error',error=str(e))\n"
              'save_json(Path(sys.argv[1]),r)\n')
    put(root / 'independent.py', script.encode())
    return old, native, bad, saved


def independent(root, candidate=None, *, approved=None, attempted=None):
    require(approved is not None, 'Missing in-memory artifact approval')
    for name, data in approved.items():
        require(contained(root, root / name).read_bytes() == data, 'Lab artifact drift')
    old = json.loads(approved['saved/legacy.json'])
    saved = {r: approved['saved/' + r + '.plist'] for r in ROLES}
    validate_inputs(root, old, saved, sys.executable)
    native = json.loads(approved['native.json'])
    selected = (root / 'production-release.json').read_bytes()
    require(json.loads(selected) in (old, native), 'Unexpected live selection')
    for role in ROLES:
        path = contained(root, root / (role + '.plist'))
        expected = plistlib.loads(saved[role])
        if json.loads(selected) == native:
            expected.pop('Program')
            expected.update(native['launchd_overrides'][role])
        require(plistlib.loads(path.read_bytes()) == expected, 'Unsafe actual plist')
    require(candidate in (None, root / 'native.json', root / 'bad-native.json'), 'Unsafe candidate')
    result = root / f'operation-{time.time_ns()}.json'
    label = f'{BUNDLE_ID}.migration.{root.name[-32:]}.controller'
    target = f'gui/{os.getuid()}/{label}'
    require(launchctl('print', target, check=False).returncode == 113, 'Controller label not absent')
    argv = [sys.executable, '-I', '-B', str(root / 'independent.py'), str(result)]
    if candidate:
        argv.append(str(candidate))
    definition = dict(Label=label, ProgramArguments=argv, WorkingDirectory=str(root),
        RunAtLoad=True, KeepAlive=False, EnvironmentVariables=environment(root),
        StandardOutPath=str(root / 'controller.out'), StandardErrorPath=str(root / 'controller.err'))
    path = root / 'controller.plist'
    path.write_bytes(plistlib.dumps(definition))
    require(attempted is not None, 'Missing controller cleanup owner')
    if target not in attempted:
        attempted.append(target)  # Outer cleanup can retry a partial bootstrap/bootout.
    try:
        launchctl('bootstrap', f'gui/{os.getuid()}', str(path))
        until(result.exists, 90)
        until(lambda: 'state = not running' in launchctl('print', target).stdout, 8)
        return json.loads(result.read_text())
    finally:
        errors = []
        try:
            launchctl('bootout', '--wait', target, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            errors.append('Controller bootout: ' + type(exc).__name__)
        try:
            require(launchctl('print', target, check=False).returncode == 113,
                    'Controller remains loaded')
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            errors.append('Controller absence: ' + type(exc).__name__)
        if errors:
            raise RuntimeError(errors)


def evidence(root):
    """Account for crash-loop receipts too; legacy ppid=1 is not a lab process."""
    ids, groups = set(), set()
    path = root / 'state/processes.jsonl'
    if path.exists():
        for line in path.read_text().splitlines():
            r = json.loads(line)
            ids.update(r[k] for k in ('pid', 'worker'))
            if r['ppid'] != 1:
                ids.add(r['ppid'])
            groups.add(r['pgid'])
    for role in ROLES:
        path = root / (role + '.out')
        if path.exists():
            for line in path.read_text().splitlines():
                if line.startswith('{'):
                    r = json.loads(line)
                    if r.get('event') == 'service-host':
                        ids.update(r[k] for k in ('pid', 'child_pid', 'guard_pid'))
                        groups.add(r['pgid'])
    require(all(type(p) is int and p > 1 for p in ids | groups), 'Unsafe process evidence')
    return ids, groups


def gone(e):
    ids, groups = e
    if not ids or not groups or any(alive(pid) for pid in ids):
        return False
    output = subprocess.run(['/bin/ps', '-axo', 'pid=,pgid='], check=True,
                            capture_output=True, text=True, timeout=10).stdout
    return not any(int(line.split()[1]) in groups for line in output.splitlines())


def verify(root, identity=IDENTITY, *, live=False):
    old, native, bad, saved = build(root, identity, live=live)
    root = Path(root)
    approved = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*')
                if p.is_file() and 'compiler' not in p.relative_to(root).parts
                and p.name not in ('production-release.json', 'agent.plist', 'webui.plist')}
    approved.update({'saved/' + r + '.plist': saved[r] for r in ROLES})
    original = (root / 'production-release.json').read_bytes()
    report = dict(status='running', synthetic_services=True, cases=[])
    targets = []
    c = Controller(root, timeout=12, stable_seconds=1)
    def snapshot(manifest):
        return c.wait_ready(manifest, c.definitions(manifest), since=None, previous=None)
    def passed(name, **fields):
        report['cases'].append(dict(name=name, passed=True, **fields))
    try:
        validate_inputs(root, old, {r: (root / (r + '.plist')).read_bytes() for r in ROLES}, sys.executable)
        c.preflight(old)
        c.preflight(native)
        c.preflight(bad)
        for role in ROLES:
            target = c.target(old, role)
            require(launchctl('print', target, check=False).returncode == 113, 'Lab label already present')
            targets.append(target)
            launchctl('bootstrap', f'gui/{os.getuid()}', str(root / (role + '.plist')))
        passed('exact_legacy_pair', snapshot=snapshot(old))
        before = evidence(root)
        started = time.monotonic()
        result = independent(root, root / 'bad-native.json', approved=approved, attempted=targets)
        require(result['status'] == 'rolled_back', 'Failed native start did not roll back')
        require(time.monotonic() - started < 90, 'Rollback exceeded bound')
        require((root / 'production-release.json').read_bytes() == original and all(
            (root / (r + '.plist')).read_bytes() == saved[r] for r in ROLES), 'Rollback bytes differ')
        restored = snapshot(old)
        # Exclude the restored legacy pair, but require failed native hosts/guards/workers gone.
        native_ids, native_groups, failed_roles = set(), set(), set()
        for role in ROLES:
            for line in (root / (role + '.out')).read_text().splitlines():
                if line.startswith('{'):
                    r = json.loads(line)
                    if r.get('event') == 'service-host':
                        native_ids.update(r[k] for k in ('pid', 'child_pid', 'guard_pid'))
                        native_groups.add(r['pgid'])
                        failed_roles.add(r['role'])
        for line in (root / 'state/processes.jsonl').read_text().splitlines():
            r = json.loads(line)
            if r['pgid'] in native_groups:
                native_ids.add(r['worker'])
        require(failed_roles == set(ROLES), 'Missing failed-native-start receipts for both roles')
        until(lambda: gone((native_ids, native_groups)) and gone(before))
        passed('failed_native_start_exact_legacy_rollback', result=result, snapshot=restored)
        before = evidence(root)
        result = independent(root, root / 'native.json', approved=approved, attempted=targets)
        require(result['status'] == 'verified', 'Migration not verified')
        proof = snapshot(native)
        require(set(proof.get('process_identity', {})) == set(ROLES), 'Missing native ownership proof')
        until(lambda: gone(before))
        pair = {r: until(lambda r=r: current(root, native, r)) for r in ROLES}
        passed('legacy_to_native_both_roles', result=result, snapshot=proof, pair=pair)
        before = evidence(root)
        result = independent(root, approved=approved, attempted=targets)
        require(result['status'] == 'verified', 'Independent native restart failed')
        proof = snapshot(native)
        until(lambda: gone(before))
        passed('independent_native_pair_restart', result=result, snapshot=proof)
        for role in ROLES:
            pair = {r: until(lambda r=r: current(root, native, r)) for r in ROLES}
            previous = copy.deepcopy(pair[role])
            sibling = 'webui' if role == 'agent' else 'agent'
            c.host.kickstart(c.target(native, role))
            def replacement():
                value = current(root, native, role)
                return value if value and value['ppid'] != previous['ppid'] else None
            renewed = until(replacement)
            until(lambda: gone(({previous[k] for k in ('pid', 'ppid', 'worker', 'guard')},
                                {previous['pgid']})))
            require(current(root, native, sibling) == pair[sibling], 'Sibling restarted unexpectedly')
            passed('independent_' + role + '_restart', old=previous, new=renewed,
                   sibling_unchanged=True, snapshot=snapshot(native))
    except BaseException as exc:
        report.update(status='failed', error=str(exc), error_type=type(exc).__name__)
        raise
    finally:
        errors = []
        for target in reversed(targets):
            try:
                launchctl('bootout', '--wait', target, check=False)
                require(launchctl('print', target, check=False).returncode == 113, 'Label remains loaded')
            except Exception as exc:
                errors.append(str(exc))
        try:
            if targets:
                until(lambda: gone(evidence(root)))
        except Exception as exc:
            errors.append('Process/group cleanup unverified: ' + str(exc))
        set_cleanup_outcome(report, errors, targets)
        if errors:
            report.update(status='failed', cleanup_errors=errors)
        elif report['status'] == 'running':
            report['status'] = 'passed'
        # A success receipt exists only after every assertion AND final cleanup.
        name = 'migration-success.json' if report['status'] == 'passed' else 'migration-failed.json'
        put(root / name, encoded(report))
        if errors:
            raise RuntimeError(errors)
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--live-synthetic', action='store_true')
    args = p.parse_args()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    print(json.dumps(verify(args.root, live=args.live_synthetic), indent=2))


if __name__ == '__main__':
    main()
