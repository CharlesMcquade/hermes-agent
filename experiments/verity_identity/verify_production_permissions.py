"""Review-required fixed-path permission experiment. No production activation.

Operator phases: prepare (--approve-sign), preflight, run (--live), recover (--live).
Imports are inert; permission APIs exist only in the sealed worker entry point.
"""
import argparse
import ctypes as C
import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import plistlib
import re
import signal
import struct
import shutil
import subprocess
import sys
import time
import uuid

SIGNER = 'B72A53676319B035EF637A6DEF27F026009D989C'
BUNDLE_ID = 'com.charles.verity'
REQUIREMENT = f'identifier "{BUNDLE_ID}" and certificate leaf = H"{SIGNER.lower()}"'
BINARY = 'Contents/MacOS/VerityServiceHost'
SETTINGS = 'Contents/Resources/service-settings.json'
NAMES = ('Full Disk Access: Messages', 'Full Disk Access: Safari', 'Accessibility',
         'Input Monitoring', 'Screen Capture', 'Contacts', 'Calendar', 'Reminders',
         'Camera', 'Microphone', 'Photos', 'Speech', 'Bluetooth', 'Location', 'Local Network')
MODES = ('permissions-check', 'permissions-request')


def check(condition, message):
    if not condition:
        raise ValueError(message)


def helpers():
    # Operator only. Worker never imports controllers, applications or maintenance.
    import install_production_native as install
    import stage_production_native as stage
    return install, stage


def sha(data):
    return hashlib.sha256(data).hexdigest()


def durable(root, name, value):
    """Every phase is retained, including the receipt before any rename."""
    install, stage = helpers()
    path = root / name
    check(not path.exists(), 'Receipt already exists')
    install.atomic_write(path, stage.encoded(value))
    sync_dir(root)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def move(source, target):
    check(not target.exists() and not target.is_symlink(), 'Rename destination exists')
    os.rename(source, target)
    sync_dir(source.parent)
    sync_dir(target.parent)


def tree(path):
    """Inventory includes directories, modes and owners, not just file hashes."""
    install, _ = helpers()
    result = {}
    for item in [path, *sorted(path.rglob('*'))]:
        install.safe(item)
        s = item.stat()
        result[str(item.relative_to(path))] = [s.st_mode & 0o777, s.st_uid,
                                              sha(item.read_bytes()) if item.is_file() else None]
    return result


def verify_signature(app, runner=None):
    _, stage = helpers()
    (runner or stage.run)(['/usr/bin/codesign', '--verify', '--strict', '-R',
                           '=' + REQUIREMENT, str(app)])


def code_payload(data):
    """Thin arm64 Mach-O: allow only the embedded signature blob to change.

    Refuse a signer that also changes layout/load commands: not a broad Mach-O
    normalizer. Original bundle is retained byte-for-byte by rename, never resigned.
    """
    check(len(data) >= 32 and struct.unpack_from('<I', data)[0] == 0xFEEDFACF,
          'Expected thin Mach-O')
    count = struct.unpack_from('<I', data, 16)[0]
    pos, signature = 32, None
    for _ in range(count):
        cmd, size = struct.unpack_from('<II', data, pos)
        check(size >= 8 and pos + size <= len(data), 'Malformed Mach-O')
        if cmd == 0x1D:
            check(signature is None and size == 16, 'Malformed signature command')
            offset, length = struct.unpack_from('<II', data, pos + 8)
            check(offset >= pos + size and offset + length == len(data), 'Signature layout changed')
            signature = (offset, length)
        pos += size
    check(signature is not None, 'Missing embedded signature')
    return data[:signature[0]]


def accessibility(probe, request):
    """Trust/status and fixed Finder AXRole only; never focused-app lookup."""
    lib, cf = probe.framework('ApplicationServices'), probe.framework('CoreFoundation')
    trusted = probe.boolean_function(lib, 'AXIsProcessTrusted')
    requested = request and not bool(trusted())
    completed = True
    cf.CFRelease.argtypes, cf.CFRelease.restype = [C.c_void_p], None
    if requested:
        keys = (C.c_void_p * 1)(C.c_void_p.in_dll(lib, 'kAXTrustedCheckOptionPrompt').value)
        values = (C.c_void_p * 1)(C.c_void_p.in_dll(cf, 'kCFBooleanTrue').value)
        cf.CFDictionaryCreate.argtypes = [C.c_void_p, C.POINTER(C.c_void_p),
                                         C.POINTER(C.c_void_p), C.c_long, C.c_void_p, C.c_void_p]
        cf.CFDictionaryCreate.restype = C.c_void_p
        options = cf.CFDictionaryCreate(None, keys, values, 1, None, None)
        check(bool(options), 'No AX options')
        lib.AXIsProcessTrustedWithOptions.argtypes = [C.c_void_p]
        lib.AXIsProcessTrustedWithOptions.restype = C.c_bool
        try:
            lib.AXIsProcessTrustedWithOptions(options)
        finally:
            cf.CFRelease(options)
        completed = probe.wait_for_change(trusted, False)
    allowed = bool(trusted())
    probe.permission('Accessibility', 'authorized' if allowed else 'not_authorized',
                     allowed, requested, None if completed else 'ConsentTimeout')
    from AppKit import NSRunningApplication
    apps = NSRunningApplication.runningApplicationsWithBundleIdentifier_('com.apple.finder')
    if not apps:
        probe.permission('Accessibility Finder role', 'target_not_running')
        return
    lib.AXUIElementCreateApplication.argtypes = [C.c_int32]
    lib.AXUIElementCreateApplication.restype = C.c_void_p
    lib.AXUIElementCopyAttributeValue.argtypes = [C.c_void_p, C.c_void_p, C.POINTER(C.c_void_p)]
    lib.AXUIElementCopyAttributeValue.restype = C.c_int32
    cf.CFStringCreateWithCString.argtypes = [C.c_void_p, C.c_char_p, C.c_uint32]
    cf.CFStringCreateWithCString.restype = C.c_void_p
    element = lib.AXUIElementCreateApplication(apps[0].processIdentifier())
    attr = cf.CFStringCreateWithCString(None, b'AXRole', 0x08000100)
    value = C.c_void_p()
    try:
        result = lib.AXUIElementCopyAttributeValue(element, attr, C.byref(value))
        probe.permission('Accessibility Finder role', int(result), result == 0 and bool(value.value))
    finally:
        for handle in (value.value, attr, element):
            if handle:
                cf.CFRelease(handle)


def validate_worker(name, mode):
    check(name in NAMES and mode in MODES, 'Unknown worker/mode')
    check(name != 'Local Network' or mode == 'permissions-request',
          'Local Network requires permissions-request; no consent-free check-only status')


def local_network(probe, request):
    """One potentially prompting TCP connect; connectivity is not TCC proof."""
    check(request is True, 'Local Network requires permissions-request')
    import socket
    status, error = 'tcp_connected', None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(5.0)
            connection.connect(('10.101.0.2', 80))
    except OSError as exc:
        status = 'tcp_failed'
        # Never expose exception text, arbitrary class names or OS details.
        error = next((kind.__name__ for kind in
                      (TimeoutError, ConnectionRefusedError, PermissionError)
                      if isinstance(exc, kind)), 'OSError')
    probe.permission('Local Network', status, None, True, error)


def worker(config):
    """One launchd-owned Python child; no worker spawning or inherited PYTHONPATH."""
    root = Path(config['root'])
    check(sys.argv[1:] == ['--worker'], 'Only fixed worker invocation permitted')
    validate_worker(config['name'], config['mode'])
    check(list(sys.version_info[:2]) == config['abi'], 'Explicit ABI/bridge mismatch')
    check(os.environ['HOME'] == str(root / 'home') and
          os.environ['HERMES_HOME'] == str(root / 'state'), 'Nonisolated worker')
    ready = dict(event='worker-ready', pid=os.getpid(), ppid=os.getppid(),
                 pgid=os.getpgrp(), nonce=os.urandom(24).hex())
    print(json.dumps(ready), flush=True)
    end = time.monotonic() + 30
    while not (root / 'GO').exists():
        check(time.monotonic() < end, 'Identity gate timeout')
        time.sleep(0.05)
    check(json.loads((root / 'GO').read_text()) == ready, 'Gate is not for this live worker')
    sys.path.insert(0, config['bridge'])
    path = root / 'permissions_probe.py'
    check(sha(path.read_bytes()) == config['probe_sha256'], 'Probe drift')
    spec = importlib.util.spec_from_file_location('bounded_permission_functions', path)
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)
    records = []
    probe.emit = lambda event, **values: records.append(dict(event=event, **values))
    name, request = config['name'], config['mode'] == 'permissions-request'
    try:
        if name in probe.FILE_PATHS:
            # Only these two os.open(O_RDONLY)/close calls use the real HOME.
            previous = os.environ['HOME']
            try:
                os.environ['HOME'] = config['home']
                probe.protected_file(name, False)
            finally:
                os.environ['HOME'] = previous
        elif name == 'Accessibility':
            accessibility(probe, request)
        elif name == 'Local Network':
            local_network(probe, request)
        elif name in ('Input Monitoring', 'Screen Capture'):
            probe.preflight(name, request)
        else:
            probe.native(name, request)
        final = sanitize(records, name)
        print(json.dumps(dict(event='worker-complete', exit_code=0, results=final)), flush=True)
        return 0
    except Exception:
        print(json.dumps(dict(event='worker-complete', exit_code=1, results=[])), flush=True)
        return 1


def sanitize(records, name):
    statuses = {'opened_read_only', 'missing', 'denied', 'authorized', 'not_authorized',
                'target_not_running', 'not_determined', 'restricted', 'limited', 'full_access',
                'write_only', 'unknown', 'authorized_always', 'authorized_when_in_use',
                'services_disabled'}
    errors = {None, 'ConsentTimeout', 'FileNotFoundError', 'EPERM', 'EACCES'}
    final = []
    for r in records:
        check(set(r) == {'event', 'name', 'status', 'allowed', 'requested', 'error_type'},
              'Bad permission record')
        check(r['event'] == 'permission' and r['name'] in (name, 'Accessibility Finder role'),
              'Unexpected result name')
        check(type(r['requested']) is bool and (r['allowed'] is None or type(r['allowed']) is bool),
              'Bad permission scalar')
        if name == 'Local Network':
            check(r['name'] == name and r['allowed'] is None and r['requested'] is True,
                  'Connectivity is not authorization')
            check((r['status'] == 'tcp_connected' and r['error_type'] is None) or
                  (r['status'] == 'tcp_failed' and r['error_type'] in
                   {'TimeoutError', 'ConnectionRefusedError', 'PermissionError', 'OSError'}),
                  'Unknown network result')
            final.append(r)
            continue
        check(r['error_type'] in errors, 'Unknown error scalar')
        if r['status'] == 'requesting':
            continue
        check(r['status'] in statuses or (r['name'] == 'Accessibility Finder role' and
                                         type(r['status']) is int), 'Unknown status scalar')
        final.append(r)
    check(any(r['name'] == name for r in final), 'No completed permission result')
    return final


def supervisor(config):
    root = Path(config['root'])
    check(sys.argv[1:] == ['agent', '--manifest', str(root / 'production-release.json')],
          'Only fixed agent invocation permitted')
    binary = root / 'permission-python'
    check(not binary.is_symlink() and sha(binary.read_bytes()) == config['worker_sha256'], 'Worker binary drift')
    env = dict(HOME=str(root / 'home'), HERMES_HOME=str(root / 'state'), TMPDIR=str(root / 'tmp'),
               PATH='/usr/bin:/bin:/usr/sbin:/sbin', PYTHONHOME=config['python_home'],
               PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1')
    # Same launchd-owned process group; frozen host guard covers this worker too.
    child = subprocess.Popen([str(binary), '-S', '-s', '-P', '-u', '-B',
                              str(root / 'production_launcher.py'), '--worker'], env=env,
                             stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(json.dumps(dict(event='supervisor-ready', pid=os.getpid(), ppid=os.getppid(),
                          pgid=os.getpgrp(), worker=child.pid)), flush=True)
    try:
        result = child.wait(timeout=480 if config['mode'] == 'permissions-request' else 50)
    except BaseException:
        child.kill()
        child.wait(timeout=5)
        raise
    print(json.dumps(dict(event='supervisor-exit', exit_code=result)), flush=True)
    return result


def launcher_source(config):
    validate_worker(config['name'], config['mode'])
    config = dict(sorted(config.items()))
    # Freeze reviewed worker functions into the hashed launcher, not control code.
    imports = ('import ctypes as C, hashlib, importlib.util, json, os, subprocess, sys, time\n'
               'from pathlib import Path\n')
    return (imports + f'NAMES={NAMES!r}\nMODES={MODES!r}\n' +
            '\n'.join(inspect.getsource(f) for f in (check, sha, accessibility, validate_worker,
                                                    local_network, sanitize, worker, supervisor)) +
            f'\nraise SystemExit((worker if sys.argv[1:] == ["--worker"] else supervisor)({config!r}))\n').encode()


def job(root, home, label):
    return dict(Label=label, ProgramArguments=[str(home / 'Applications/Verity.app' / BINARY), 'agent'],
                WorkingDirectory=str(root), RunAtLoad=True, KeepAlive=False,
                AssociatedBundleIdentifiers=[BUNDLE_ID], AbandonProcessGroup=False,
                StandardOutPath=str(root / 'agent.out'), StandardErrorPath='/dev/null')


def prepare(root, base, home, python, bridge, name, mode, *, python_home=None, abi='3.11', approve_sign=False, runner=None):
    check(approve_sign is True, 'Explicit --approve-sign required')
    validate_worker(name, mode)
    install, stage = helpers()
    root, base, home = Path(root), install.safe(base), install.safe(home)
    check(root.parent == home / '.hermes/experiments', 'NEW durable experiments root required')
    install.safe(root.parent)
    install.safe(root, missing=True)
    check(not root.exists(), 'NEW root required')
    check(python_home is not None and abi in ('3.11', '3.14'), 'Explicit Python home/ABI required')
    python_home = install.safe(python_home)
    worker_binary = install.safe((python_home / 'bin' / ('python' + abi)).resolve(strict=True))
    check(worker_binary.is_file(), 'Missing real worker executable')
    python, bridge = install.safe(python), install.safe(bridge)
    check(python.is_file() and os.access(python, os.X_OK) and bridge.is_dir(), 'Explicit runtime/bridge required')
    app = install.safe(home / 'Applications/Verity.app')
    check(app.parent.stat().st_dev == root.parent.stat().st_dev, 'Swap requires one filesystem')
    check((app / 'Contents/Info.plist').read_bytes() == plistlib.dumps(stage.production_info_plist()),
          'Noncanonical production Info.plist')
    verify_signature(app, runner)
    original = tree(app)
    root.mkdir(mode=0o700)
    config = dict(root=str(root), home=str(home), python=str(python), bridge=str(bridge), name=name, mode=mode,
                  probe_sha256=sha((Path(__file__).parent / 'permissions_probe.py').read_bytes()),
                  python_home=str(python_home), abi=[int(v) for v in abi.split('.')],
                  worker_sha256=sha(worker_binary.read_bytes()))
    plan = dict(schema=1, root=str(root), base=str(base), home=str(home), config=config,
                label='com.charles.verity.permissiontest.' + uuid.uuid4().hex,
                original=original, requirement=REQUIREMENT)
    durable(root, 'prepare-start.json', plan)
    for directory in ('home', 'state', 'tmp'):
        (root / directory).mkdir(mode=0o700)
    shutil.copyfile(worker_binary, root / 'permission-python')
    (root / 'permission-python').chmod(0o700)
    stage.put(root / 'permissions_probe.py', (Path(__file__).parent / 'permissions_probe.py').read_bytes())
    stage.put(root / 'production_launcher.py', launcher_source(config))
    stage.put(root / 'production-release.json', b'{}\n')
    stage.put(root / 'agent.plist', plistlib.dumps(job(root, home, plan['label'])))
    install.copy_tree(app, root / 'Verity.app')
    settings = dict(base=str(root), bootstrap_python=str(python), launcher=str(root / 'production_launcher.py'),
                    launcher_sha256=sha((root / 'production_launcher.py').read_bytes()), roles=['agent', 'webui'])
    install.atomic_write(root / 'Verity.app' / SETTINGS, stage.encoded(settings))
    stage.put(root / 'requirements.txt', ('designated => ' + REQUIREMENT + '\n').encode())
    (runner or stage.run)(['/usr/bin/codesign', '--force', '--sign', SIGNER, '--timestamp=none',
                          '--requirements', str(root / 'requirements.txt'), str(root / 'Verity.app')])
    verify_signature(root / 'Verity.app', runner)
    check(code_payload((app / BINARY).read_bytes()) == code_payload((root / 'Verity.app' / BINARY).read_bytes()),
          'Executable code/layout changed while signing')
    check(tree(app) == original, 'Original changed during preparation')
    plan.update(temporary=tree(root / 'Verity.app'), launcher_sha256=settings['launcher_sha256'])
    durable(root, 'prepared.json', plan)
    return plan


def preflight(root, runner=None):
    install, stage = helpers()
    root = install.safe(root)
    p = json.loads(install.safe(root / 'prepared.json').read_text())
    home, base = install.safe(Path(p['home'])), install.safe(Path(p['base']))
    check(p['schema'] == 1 and p['root'] == str(root) and root.parent == home / '.hermes/experiments',
          'Foreign plan')
    check(p['requirement'] == REQUIREMENT and re.fullmatch(r'com\.charles\.verity\.permissiontest\.[0-9a-f]{32}', p['label']),
          'Foreign identity')
    check(p['config']['root'] == str(root) and p['config']['home'] == str(home) and
          p['config']['name'] in NAMES and p['config']['mode'] in MODES, 'Foreign worker')
    validate_worker(p['config']['name'], p['config']['mode'])
    check((root / 'production_launcher.py').read_bytes() == launcher_source(p['config']) and
          sha((root / 'production_launcher.py').read_bytes()) == p['launcher_sha256'], 'Launcher changed')
    check(sha((root / 'permissions_probe.py').read_bytes()) == p['config']['probe_sha256'], 'Probe changed')
    check(not (root / 'permission-python').is_symlink() and
          sha((root / 'permission-python').read_bytes()) == p['config']['worker_sha256'], 'Worker binary changed')
    check((root / 'agent.plist').read_bytes() == plistlib.dumps(job(root, home, p['label'])), 'Job changed')
    for name in ('home', 'state', 'tmp'):
        install.safe(root / name)
    expected = dict(base=str(root), bootstrap_python=p['config']['python'], launcher=str(root / 'production_launcher.py'),
                    launcher_sha256=p['launcher_sha256'], roles=['agent', 'webui'])
    app = root / 'Verity.app'
    check(tree(app) == p['temporary'] and (app / SETTINGS).read_bytes() == stage.encoded(expected),
          'Unsealed/unsafe isolated settings')
    check((app / 'Contents/Info.plist').read_bytes() == plistlib.dumps(stage.production_info_plist()), 'Metadata changed')
    verify_signature(app, runner)
    return p, base, home


def records(root):
    path = root / 'agent.out'
    if not path.exists():
        return []
    check(path.stat().st_size < 65536, 'Unexpected output volume')
    return [json.loads(line) for line in path.read_text().splitlines() if line.startswith('{')]


class Live:
    """Small read-only identity / bounded launchctl adapter, replaced in unit tests."""
    def command(self, *args):
        return subprocess.run(['/bin/launchctl', *args], capture_output=True, text=True, timeout=30)

    def absent(self, target):
        result = self.command('print', target)
        # Do not equate arbitrary launchctl failure with absence.
        return result.returncode == 113 and 'Could not find service' in result.stderr

    def bootstrap(self, target, root):
        result = self.command('bootstrap', target.rsplit('/', 1)[0], str(root / 'agent.plist'))
        check(result.returncode == 0, 'Bootstrap failed; cleanup still required')

    def identity(self, root, p):
        install, _ = helpers()
        host = next((r for r in records(root) if r.get('event') == 'service-host'), None)
        ready = next((r for r in records(root) if r.get('event') == 'worker-ready'), None)
        supervisor_record = next((r for r in records(root) if r.get('event') == 'supervisor-ready'), None)
        if host is None or ready is None or supervisor_record is None:
            return False
        check(host['role'] == 'agent' and host['pid'] == host['pgid'] == ready['pgid'] == supervisor_record['pgid'] and
              ready['ppid'] == supervisor_record['pid'] == host['child_pid'] and
              ready['pid'] == supervisor_record['worker'], 'Wrong chain')
        kernel = install.Controller(Path(p['base'])).host
        exe = str(Path(p['home']) / 'Applications/Verity.app' / BINARY)
        loaded = self.command('print', f'gui/{os.getuid()}/' + p['label'])
        match = re.search(r'^\s*pid = (\d+)$', loaded.stdout, re.M)
        check(loaded.returncode == 0 and match is not None and int(match[1]) == host['pid'], 'Wrong loaded job PID')
        first = {}
        for pid, parent, executable, argv in (
            (host['pid'], 1, exe, [exe, 'agent']),
            (host['child_pid'], host['pid'], p['config']['python'],
             [p['config']['python'], '-I', '-B', str(root / 'production_launcher.py'), 'agent',
              '--manifest', str(root / 'production-release.json')]),
            (ready['pid'], host['child_pid'], str(root / 'permission-python'),
             [str(root / 'permission-python'), '-S', '-s', '-P', '-u', '-B',
              str(root / 'production_launcher.py'), '--worker']),
        ):
            r = kernel.process_identity(pid)
            check(r['uid'] == os.getuid() and r['ppid'] == parent and r['executable'] == executable and
                  r['argv'] == argv and os.getpgid(pid) == host['pid'], 'Kernel identity mismatch')
            first[pid] = r
        guard = kernel.process_identity(host['guard_pid'])
        check(guard['uid'] == os.getuid() and guard['ppid'] == host['pid'] and guard['executable'] == exe and
              len(guard['argv']) == 4 and guard['argv'][:2] == [exe, '--group-guard'] and
              all(v.isdecimal() for v in guard['argv'][2:]) and os.getpgid(guard['pid']) == host['pid'],
              'Guard identity mismatch')
        first[guard['pid']] = guard
        check(all(kernel.process_identity(pid) == r for pid, r in first.items()), 'Identity changed')
        return True

    def exited(self, p):
        result = self.command('print', f'gui/{os.getuid()}/' + p['label'])
        if result.returncode != 0 or re.search(r'^\s*pid = (\d+)$', result.stdout, re.M):
            return None
        match = re.search(r'^\s*last exit code = (\d+)$', result.stdout, re.M)
        if match is None:
            return None
        return {'exit_code': int(match[1])}

    def cleanup(self, target, root):
        # A timeout/spawn error does not prove bootout failed. Still perform both
        # independent absence checks; neither a return code nor missing logs is proof.
        try:
            self.command('bootout', '--wait', target)
        except (OSError, subprocess.SubprocessError):
            pass
        wait(lambda: self.absent(target), 20)
        wait(lambda: process_tree_gone(root), 20)
        return True

    def restorable(self, root, p):
        return self.absent(f'gui/{os.getuid()}/' + p['label']) and process_tree_gone(root)


def process_census():
    output = subprocess.run(['/bin/ps', '-axo', 'pid=,uid=,pgid='], check=True,
                            capture_output=True, text=True, timeout=5).stdout
    rows = {}
    for line in output.splitlines():
        pid, uid, group = map(int, line.split())
        check(pid > 0 and uid >= 0 and group >= 0 and pid not in rows, 'Malformed process census')
        rows[pid] = (uid, group)
    check(os.getpid() in rows, 'Incomplete process census')
    return rows


def kernel_identity(pid):
    from native_identity import process_identity
    return process_identity(pid)


def process_tree_gone(root):
    # Independent kernel census handles failure before the first event. No
    # private content or process environments are returned or persisted.
    install, _ = helpers()
    plan = json.loads(install.safe(root / 'prepared.json').read_text())
    check(plan['root'] == str(root) and root.parent == Path(plan['home']) / '.hermes/experiments',
          'Foreign absence plan')
    app = Path(plan['home']) / 'Applications/Verity.app'
    events = records(root)
    ids, groups = set(), set()
    for r in events:
        if r.get('event') == 'service-host':
            ids.update(r[k] for k in ('pid', 'child_pid', 'guard_pid'))
            groups.add(r['pgid'])
        if r.get('event') == 'worker-ready':
            ids.add(r['pid'])
            groups.add(r['pgid'])
        if r.get('event') == 'supervisor-ready':
            ids.update((r['pid'], r['worker']))
            groups.add(r['pgid'])
    census = process_census()
    if ids.intersection(census) or any(group in groups for _, group in census.values()):
        return False
    for pid, (uid, _) in census.items():
        if uid != os.getuid():
            continue
        try:
            r = kernel_identity(pid)
        except Exception:
            # An exited process is not an unreadable live process. PID reuse or
            # any still-present unreadable identity stays unknown and refuses.
            if pid not in process_census():
                continue
            state = subprocess.run(['/bin/ps', '-p', str(pid), '-o', 'stat='], check=True,
                                   capture_output=True, text=True, timeout=5).stdout.split()
            if len(state) == 1 and state[0].startswith('Z'):
                # Positive kernel zombie status: no executable/address space.
                # Recorded experiment PIDs/groups above still require disappearance.
                continue
            return False
        check(r['pid'] == pid and r['uid'] == uid, 'Process identity/census mismatch')
        executable = Path(r['executable'])
        if executable.is_relative_to(app) or executable.is_relative_to(root):
            return False
        if str(root / 'production_launcher.py') in r['argv']:
            return False
    return True


def wait(predicate, seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        value = predicate()
        if value:
            return value
        time.sleep(0.05)
    raise TimeoutError('Bounded phase expired')


def baseline(base):
    install, _ = helpers()
    install.terminal_activation(base)
    old = json.loads((base / 'production-release.json').read_text())
    return old, {str(p): install.snapshot(p) for p in install.baseline_paths(base, old)}


def unchanged(base, old, saved, dependency=None):
    install, _ = helpers()
    install.terminal_activation(base)
    check(all(install.snapshot(Path(p)) == value for p, value in saved.items()), 'Legacy baseline changed')
    if dependency is not None:
        check(dependency(base, old) is True, 'Native dependency cannot be ruled out')


def restore_bundle(root, p, runner=None):
    """Deterministic rename recovery; original and retired temporary are never deleted."""
    app = Path(p['home']) / 'Applications/Verity.app'
    original, retired = root / 'original.app', root / 'retired.app'
    if original.exists():
        check(tree(original) == p['original'], 'Saved original drift')
        verify_signature(original, runner)
        if app.exists():
            check(tree(app) == p['temporary'], 'Final path foreign/drifted')
            move(app, retired)
        move(original, app)
    check(tree(app) == p['original'], 'Restored original inventory mismatch')
    verify_signature(app, runner)


def run(root, *, live=False, runner=None, adapter=None, dependency=None):
    check(live is True, 'Explicit --live required; preparation is not execution')
    install, _ = helpers()
    root = Path(root)
    p, base, home = preflight(root, runner)
    install.safe(base / 'control.lock')
    adapter = adapter or Live()
    dependency = dependency or install.no_live_native_dependency
    target = f'gui/{os.getuid()}/' + p['label']
    with install.control_lock(base):
        old, saved = baseline(base)
        unchanged(base, old, saved, dependency)
        app = home / 'Applications/Verity.app'
        check(tree(app) == p['original'], 'Original inventory drift')
        verify_signature(app, runner)
        for name in ('swap-receipt.json', 'original.app', 'retired.app', 'GO', 'agent.out'):
            install.safe(root / name, missing=True)
            check(not (root / name).exists(), 'Existing run destination; recover instead')
        check(adapter.absent(target), 'Target exists or absence unknown')
        receipt = dict(plan=p, baseline=saved, old=old, target=target)
        durable(root, 'swap-receipt.json', receipt)  # Before any swap or bootstrap.
        attempted, cleaned = False, False
        report = dict(status='failed', cleanup_verified=False, restored=False,
                      permission_authorization_is_not_task_authorization=True)
        try:
            move(app, root / 'original.app')
            move(root / 'Verity.app', app)
            check(tree(app) == p['temporary'], 'Temporary final-path inventory mismatch')
            verify_signature(app, runner)
            unchanged(base, old, saved, dependency)
            attempted = True  # Before durable intent too: interruption may follow its write.
            durable(root, 'bootstrap-intent.json', {'target': target})
            adapter.bootstrap(target, root)
            wait(lambda: adapter.identity(root, p), 20)
            ready = next(r for r in records(root) if r.get('event') == 'worker-ready')
            durable(root, 'GO', ready)
            complete = wait(lambda: next((r for r in records(root) if r.get('event') == 'worker-complete'), None),
                            450 if p['config']['mode'] == 'permissions-request' else 20)
            check(complete['exit_code'] == 0, 'Worker failed')
            results = sanitize(complete['results'], p['config']['name'])
            exited = wait(lambda: next((r for r in records(root) if r.get('event') == 'service-exit'), None), 5)
            check(exited['status'] == 0, 'Host child did not exit cleanly')
            host_exit = wait(lambda: adapter.exited(p), 10)
            check(host_exit['exit_code'] == 0, 'Launchd host exit not clean')
            report.update(status='incomplete' if any(r['error_type'] == 'ConsentTimeout' for r in results) else 'completed',
                          results=results, worker_exit=0, host_child_exit=0, host_exit=0)
        except BaseException as exc:
            report['error_type'] = type(exc).__name__
        finally:
            try:
                if attempted:
                    cleaned = adapter.cleanup(target, root) is True
                    check(cleaned, 'Cleanup unverified')
                else:
                    cleaned = True
                report['cleanup_verified'] = cleaned
                # Restoration needs unchanged legacy selection and absence of
                # artifact users, not healthy unrelated legacy service PIDs.
                unchanged(base, old, saved)
                check(adapter.restorable(root, p) is True, 'Artifact users remain or unknown')
                restore_bundle(root, p, runner)
                report['restored'] = True
                unchanged(base, old, saved)
            except BaseException as exc:
                report.update(status='failed', recovery_error_type=type(exc).__name__)
            # Failure here cannot undo a verified restoration; receipt remains.
            durable(root, 'result.json', report)
        return report


def recover(root, *, live=False, runner=None, adapter=None, dependency=None):
    check(live is True, 'Explicit --live required for recovery')
    install, _ = helpers()
    root = install.safe(root)
    receipt = json.loads(install.safe(root / 'swap-receipt.json').read_text())
    p = receipt['plan']
    check(p == json.loads((root / 'prepared.json').read_text()) and p['root'] == str(root) and
          root.parent == Path(p['home']) / '.hermes/experiments' and p['requirement'] == REQUIREMENT,
          'Foreign recovery receipt')
    check(re.fullmatch(r'com\.charles\.verity\.permissiontest\.[0-9a-f]{32}', p['label']) is not None and
          receipt['target'] == f'gui/{os.getuid()}/' + p['label'], 'Foreign cleanup target')
    base = install.safe(Path(p['base']))
    install.safe(base / 'control.lock')
    adapter = adapter or Live()
    # dependency is retained for API compatibility, but live legacy availability
    # is admission-only. Stop the exactly-owned experiment before checking drift.
    with install.control_lock(base):
        if (root / 'bootstrap-intent.json').exists():
            check(adapter.cleanup(receipt['target'], root) is True, 'Cleanup unknown; retaining original')
        else:
            check(adapter.absent(receipt['target']), 'Unexpected target')
        check(baseline(base) == (receipt['old'], receipt['baseline']), 'Incomplete or changed recovery baseline')
        unchanged(base, receipt['old'], receipt['baseline'])
        check(adapter.restorable(root, p) is True, 'Artifact users remain or unknown')
        restore_bundle(root, p, runner)
        unchanged(base, receipt['old'], receipt['baseline'])
        report = dict(status='restored', cleanup_verified=True, restored=True)
        durable(root, 'recovery-' + uuid.uuid4().hex + '.json', report)
        return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('prepare', 'preflight', 'run', 'recover'))
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--base', type=Path)
    parser.add_argument('--home', type=Path)
    parser.add_argument('--python', type=Path)
    parser.add_argument('--bridge', type=Path)
    parser.add_argument('--python-home', type=Path)
    parser.add_argument('--abi', choices=('3.11', '3.14'), default='3.11')
    parser.add_argument('--worker', choices=NAMES)
    parser.add_argument('--mode', choices=MODES, default='permissions-check')
    parser.add_argument('--approve-sign', action='store_true')
    parser.add_argument('--live', action='store_true')
    args = parser.parse_args(argv)
    if args.phase == 'prepare':
        if any(getattr(args, n) is None for n in ('base', 'home', 'python', 'bridge', 'worker', 'python_home')):
            parser.error('prepare requires --base --home --python --bridge --worker')
        prepare(args.root, args.base, args.home, args.python, args.bridge, args.worker, args.mode,
                python_home=args.python_home, abi=args.abi, approve_sign=args.approve_sign)
        result = dict(status='prepared_not_run')
    elif args.phase == 'preflight':
        preflight(args.root)
        result = dict(status='preflight_not_run')
    else:
        # Ordinary first interrupt runs finally; repeated interrupts are not guaranteed safe.
        def interrupted(signum, frame):
            raise KeyboardInterrupt()
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, interrupted)
        result = (run if args.phase == 'run' else recover)(args.root, live=args.live)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] in ('prepared_not_run', 'preflight_not_run', 'completed', 'restored') else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps(dict(status='failed', error_type=type(exc).__name__)))
        raise SystemExit(1)
