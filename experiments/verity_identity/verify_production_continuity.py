"""Bounded A/B/A final-identity continuity; synthetic roles, never real services.

Not a cutover tool. Prepare/sign and run/recover require separate opt-ins.
"""
import argparse
import ast
import hashlib
import inspect
import json
import math
import os
from pathlib import Path
import plistlib
import re
import signal
import struct
import subprocess
import sys
import time
import uuid

import verify_production_permissions as base

NAMES = ('Full Disk Access: Messages', 'Full Disk Access: Safari', 'Accessibility',
         'Input Monitoring', 'Screen Capture', 'Contacts', 'Calendar', 'Reminders',
         'Camera', 'Microphone', 'Photos', 'Speech', 'Bluetooth', 'Automation: Finder')
MATRIX = tuple((build, role, abi) for build in ('A', 'B', 'A')
               for role in ('agent', 'webui') for abi in ('3.11', '3.14'))
check = base.check
base_sha = base.sha
SOURCE = Path(__file__).resolve().parent
RECEIPT_LIMIT = 4 * 1024 * 1024
SIGNING_RECEIPT_RESERVE = 512 * 1024


def text_section(data):
    """Only thin arm64 executable __TEXT,__text; signatures/UUIDs are irrelevant."""
    check(len(data) >= 32, 'Short Mach-O')
    magic, cpu, _, kind, count, size, _, _ = struct.unpack_from('<8I', data)
    check((magic, cpu, kind) == (0xFEEDFACF, 0x0100000C, 2), 'Wrong executable format')
    end = 32 + size
    check(0 < count <= 4096 and end <= len(data), 'Invalid load commands')
    pos, found = 32, []
    for _ in range(count):
        check(pos + 8 <= end, 'Truncated command')
        cmd, length = struct.unpack_from('<II', data, pos)
        check(length >= 8 and length % 8 == 0 and pos + length <= end, 'Invalid command')
        if cmd == 0x19:
            check(length >= 72, 'Short segment')
            segment = data[pos + 8:pos + 24].rstrip(b'\0')
            fileoff, filesize = struct.unpack_from('<QQ', data, pos + 40)
            _, protection, sections, _ = struct.unpack_from('<4I', data, pos + 56)
            check(length == 72 + 80 * sections and fileoff + filesize <= len(data), 'Invalid segment')
            for i in range(sections):
                at = pos + 72 + i * 80
                name = data[at:at + 16].rstrip(b'\0')
                owner = data[at + 16:at + 32].rstrip(b'\0')
                if name == b'__text' and owner == b'__TEXT':
                    length_text = struct.unpack_from('<Q', data, at + 40)[0]
                    offset = struct.unpack_from('<I', data, at + 48)[0]
                    flags = struct.unpack_from('<I', data, at + 64)[0]
                    check(segment == b'__TEXT' and protection & 4 and flags & 0x80000000
                          and flags & 0xff == 0 and length_text > 0
                          and end <= offset and fileoff <= offset
                          and offset + length_text <= fileoff + filesize, 'Non-executable text')
                    found.append(data[offset:offset + length_text])
        pos += length
    check(pos == end and len(found) == 1, 'Missing/duplicate executable text')
    return found[0]


def compile_alternative(root, source, binary, runner):
    # Reuse stager isolation, altering only one fixed compiler optimization flag.
    _, stage = base.helpers()
    def optimized(argv, *, env):
        check(argv[:3] == ['/usr/bin/xcrun', '--no-cache', 'swiftc'], 'Unexpected compiler')
        env = dict(env)
        for key, name in (('HERMES_HOME', 'state'), ('HERMES_WEBUI_STATE_DIR', 'webui-state')):
            directory = root / 'compiler' / name
            directory.mkdir(mode=0o700)
            env[key] = str(directory)
        runner(argv[:3] + ['-O'] + argv[3:], env=env)
    stage.compile_host(root, source, binary, runner=optimized)


def dependency_inventory(root):
    """Pin explicit runtime/bridge files, permitting only in-tree file symlinks.

    Directory symlinks and escaping links refuse instead of widening the read set.
    No module is imported and no interpreter is executed by inventory collection.
    """
    install, _ = base.helpers()
    root = install.safe(root)
    items = sorted(root.rglob('*'))
    check(root.is_dir() and len(items) <= 100000, 'Unbounded dependency tree')
    result = {}
    for item in [root, *items]:
        link = None
        if item.is_symlink():
            resolved = item.resolve(strict=True)
            check(resolved.is_relative_to(root) and resolved.is_file(), 'Escaping/directory dependency link')
            install.safe(resolved)
            link = os.readlink(item)
            source = resolved
        else:
            source = install.safe(item)
        st = item.lstat()
        check(st.st_uid == os.getuid() and not st.st_mode & 0o022 if link is None else st.st_uid == os.getuid(),
              'Unsafe dependency owner/mode')
        digest = None
        if source.is_file():
            import hashlib
            value = hashlib.sha256()
            with source.open('rb') as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    value.update(chunk)
            digest = value.hexdigest()
        result[str(item.relative_to(root))] = [st.st_mode, st.st_uid, link, digest]
    return result


def verify_inputs(root, p):
    install, _ = base.helpers()
    python = install.safe(Path(p['bootstrap']))
    check(base.sha(python.read_bytes()) == p['bootstrap_sha256'], 'Bootstrap drift')
    roots = {}
    for path, expected in p['dependencies'].items():
        roots[path] = Path(path).stat()
        check(dependency_inventory(Path(path)) == expected, 'Runtime/bridge dependency drift')
        check(Path(path).stat() == roots[path], 'Dependency root changed during validation')
    for name, digest in p['sealed'].items():
        path = root / name
        check(not Path(name).is_absolute() and '..' not in Path(name).parts, 'Foreign seal path')
        install.safe(path)
        check(base.sha(path.read_bytes()) == digest, 'Sealed input drift')
    return roots


def verify_gate_inputs(root, p, i, roots, deadline):
    """Fixed point-of-use set; no transitive traversal while the worker waits.

    Deadline checks cannot preempt a stuck filesystem syscall, but prevent GO
    after it returns late. The full inventory is checked before bootstrap.
    """
    install, _ = base.helpers()
    check(len(roots) <= 4, 'Unexpected dependency roots')
    for path, stamp in roots.items():
        check(install.safe(Path(path)).stat() == stamp, 'Dependency root drift')
    case = case_dir(root, i)
    files = [(Path(p['bootstrap']), p['bootstrap_sha256'])]
    for path in [root / 'production_launcher.py', root / 'production-release.json',
                 *[case / n for n in ('permission-python', 'production_launcher.py',
                                      'permissions_probe.py', 'agent.plist')]]:
        files.append((path, p['sealed'][str(path.relative_to(root))]))
    budget = 64 * 1024 * 1024
    for path, digest in files:
        check(time.monotonic() < deadline, 'Identity gate deadline')
        install.safe(path)
        size = path.stat().st_size
        check(0 <= size <= budget, 'Oversized point-of-use input')
        value = hashlib.sha256()
        with path.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                budget -= len(chunk)
                check(budget >= 0 and time.monotonic() < deadline, 'Identity gate budget')
                value.update(chunk)
        check(value.hexdigest() == digest, 'Point-of-use input drift')
    check(time.monotonic() < deadline, 'Identity gate deadline')


def receipt_size(value):
    # Use the exact durable writer's encoding (including indentation/escaping).
    _, stage = base.helpers()
    return len(stage.encoded(value))


def durable(root, name, value):
    check(receipt_size(value) <= RECEIPT_LIMIT, 'Oversized receipt')
    base.durable(root, name, value)


def read_json(path):
    install, _ = base.helpers()
    install.safe(path)
    with path.open('rb') as stream:
        data = stream.read(RECEIPT_LIMIT + 1)
    check(len(data) <= RECEIPT_LIMIT, 'Oversized receipt')
    return json.loads(data)


def case_dir(root, index):
    check(type(index) is int and 0 <= index < len(MATRIX), 'Unknown matrix case')
    return root / 'cases' / f'{index:02d}'


def select_case(root, configs):
    # Sealed table, not a config/command supplied by a live caller. Exclusive
    # intent is append-only; completed entries can never be selected again.
    active = [i for i in range(len(configs))
              if (Path(root) / 'cases' / f'{i:02d}' / 'intent.json').exists()
              and not (Path(root) / 'cases' / f'{i:02d}' / 'result.json').exists()]
    check(len(active) == 1, 'No unique unfinished case')
    i = active[0]
    check(all((Path(root) / 'cases' / f'{j:02d}' / 'result.json').exists() for j in range(i)),
          'Out of order case')
    return configs[i]


def continuity_supervisor(root, configs):
    config = select_case(root, configs)
    check(sys.argv[1:] == [config['role'], '--manifest', str(Path(root) / 'production-release.json')],
          'Wrong synthetic role invocation')
    case = Path(config['root'])
    binary = case / 'permission-python'
    check(not binary.is_symlink() and base_sha(binary.read_bytes()) == config['worker_sha256'], 'Runtime drift')
    env = dict(HOME=str(case / 'home'), HERMES_HOME=str(case / 'state'), TMPDIR=str(case / 'tmp'),
               HERMES_WEBUI_STATE_DIR=str(case / 'webui-state'),
               PATH='/usr/bin:/bin:/usr/sbin:/sbin', PYTHONHOME=config['python_home'],
               PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1')
    child = subprocess.Popen([str(binary), '-S', '-s', '-P', '-u', '-B',
                              str(case / 'production_launcher.py'), '--worker'], env=env,
                             stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(json.dumps(dict(event='supervisor-ready', pid=os.getpid(), ppid=os.getppid(),
                          pgid=os.getpgrp(), worker=child.pid)), flush=True)
    try:
        result = child.wait(timeout=50)
    except BaseException:
        child.kill()
        child.wait(timeout=5)
        raise
    print(json.dumps(dict(event='supervisor-exit', exit_code=result)), flush=True)
    return result


def launcher_source(root, configs):
    configs = [dict(sorted(c.items())) for c in configs]
    imports = 'import hashlib,json,os,subprocess,sys\nfrom pathlib import Path\n'
    return (imports + inspect.getsource(check) + '\n'
            + 'def base_sha(data):\n    return hashlib.sha256(data).hexdigest()\n'
            + inspect.getsource(select_case) + '\n' + inspect.getsource(continuity_supervisor)
            + f'\nraise SystemExit(continuity_supervisor({str(root)!r}, {configs!r}))\n').encode()


def worker_source(config):
    config = dict(sorted(config.items()))
    # Retain the base's proven worker and its fixed --worker/nonce/GO protocol.
    # Remove only the base entry expression; no worker function rewriting.
    tree = ast.parse(base.launcher_source(config))
    check(isinstance(tree.body[-1], ast.Raise), 'Base launcher contract changed')
    tree.body.pop()
    source = ast.unparse(tree)
    return (source + f'\ncheck(sys.argv[1:] == ["--worker"], "Worker only")\n'
            + f'raise SystemExit(worker({config!r}))\n').encode()


def definition(root, home, label, role):
    result = base.job(root, home, label)
    result['ProgramArguments'][-1] = role
    return result


def settings(root, python, launcher_hash):
    return dict(base=str(root), bootstrap_python=str(python),
                launcher=str(root / 'production_launcher.py'), launcher_sha256=launcher_hash,
                roles=['agent', 'webui'])


def prepare(root, maintenance, home, python, runtimes, bridges, name, *, approve_sign=False, runner=None):
    check(approve_sign is True, 'Explicit --approve-sign required')
    check(name in NAMES and name in base.NAMES, 'Worker unavailable or disallowed')
    check(set(runtimes) == set(bridges) == {'3.11', '3.14'}, 'Both explicit ABIs required')
    install, stage = base.helpers()
    runner = runner or stage.run
    root, maintenance, home = Path(root), install.safe(maintenance), install.safe(home)
    check(root.parent == home / '.hermes/experiments', 'Fresh durable root required')
    install.safe(root.parent)
    install.safe(root, missing=True)
    check(not root.exists(), 'Root already used')
    python = install.safe(python)
    check(python.is_file() and os.access(python, os.X_OK), 'Invalid bootstrap')
    app = install.safe(home / 'Applications/Verity.app')
    check(app.parent.stat().st_dev == root.parent.stat().st_dev, 'Different filesystems')
    canonical = plistlib.dumps(stage.production_info_plist())
    check((app / 'Contents/Info.plist').read_bytes() == canonical, 'Noncanonical metadata')
    base.verify_signature(app, runner)
    original = base.tree(app)
    original_code = (app / base.BINARY).read_bytes()
    original_text = text_section(original_code)
    inputs = {}
    for abi in ('3.11', '3.14'):
        runtime, bridge = install.safe(runtimes[abi]), install.safe(bridges[abi])
        binary = install.safe((runtime / 'bin' / ('python' + abi)).resolve(strict=True))
        check(binary.is_file() and os.access(binary, os.X_OK) and bridge.is_dir(), 'Invalid ABI inputs')
        inputs[abi] = dict(home=str(runtime), bridge=str(bridge), binary=str(binary),
                           sha256=base.sha(binary.read_bytes()))
    dependencies = {str(path): dependency_inventory(path) for path in
                    {Path(v[k]) for v in inputs.values() for k in ('home', 'bridge')}}
    root.mkdir(mode=0o700)
    plan = dict(schema=1, root=str(root), base=str(maintenance), home=str(home), name=name,
                original=original, requirement=base.REQUIREMENT, matrix=[list(v) for v in MATRIX],
                label='com.charles.verity.continuity.' + uuid.uuid4().hex,
                bootstrap=str(python), bootstrap_sha256=base.sha(python.read_bytes()), inputs=inputs,
                dependencies=dependencies)
    durable(root, 'prepare-start.json', plan)
    for directory in ('home', 'state', 'tmp', 'cases', 'builds'):
        (root / directory).mkdir(mode=0o700)
    configs = []
    probe = (SOURCE / 'permissions_probe.py').read_bytes()
    for i, (_, role, abi) in enumerate(MATRIX):
        case = case_dir(root, i)
        case.mkdir(mode=0o700)
        for directory in ('home', 'state', 'tmp', 'webui-state'):
            (case / directory).mkdir(mode=0o700)
        data = Path(inputs[abi]['binary']).read_bytes()
        check(base.sha(data) == inputs[abi]['sha256'], 'Source runtime drift')
        stage.put(case / 'permission-python', data)
        (case / 'permission-python').chmod(0o700)
        config = dict(root=str(case), home=str(home), name=name, mode='permissions-check', role=role,
                      abi=[int(v) for v in abi.split('.')], bridge=inputs[abi]['bridge'],
                      python_home=inputs[abi]['home'], worker_sha256=base.sha(data),
                      probe_sha256=base.sha(probe))
        configs.append(config)
        stage.put(case / 'permissions_probe.py', probe)
        stage.put(case / 'production_launcher.py', worker_source(config))
        stage.put(case / 'agent.plist', plistlib.dumps(definition(case, home, plan['label'] + f'.{i:02d}', role)))
    launcher = launcher_source(root, configs)
    stage.put(root / 'production_launcher.py', launcher)
    stage.put(root / 'production-release.json', b'{}\n')
    shared_settings = stage.encoded(settings(root, python, base.sha(launcher)))
    stage.put(root / 'requirements.txt', ('designated => ' + base.REQUIREMENT + '\n').encode())
    swift = (SOURCE / 'ServiceHost.swift').read_bytes()
    stage.put(root / 'ServiceHost.swift', swift)
    # All variable input sizes are known before the first signing/compilation.
    # Reserve additional signature-inventory space, then enforce the exact final
    # encoding too: an unexpectedly expansive signer may fail, never publish.
    sealed = {str(p.relative_to(root)): base.sha(p.read_bytes()) for p in root.rglob('*')
              if p.is_file() and ('cases' in p.relative_to(root).parts
                                 or p.name in ('production_launcher.py', 'production-release.json',
                                               'ServiceHost.swift', 'requirements.txt'))}
    projected = dict(plan, configs=configs, sealed=sealed, builds={'A': original, 'B': original},
                     text_sha256={'A': '0' * 64, 'B': '0' * 64},
                     source_sha256=base.sha(swift), launcher_sha256=base.sha(launcher))
    check(receipt_size(projected) + SIGNING_RECEIPT_RESERVE <= RECEIPT_LIMIT,
          'Insufficient final receipt budget before signing')
    inventories, text_hashes = {}, {}
    for build in ('A', 'B'):
        target = root / 'builds' / (build + '.app')
        install.copy_tree(app, target)
        install.atomic_write(target / base.SETTINGS, shared_settings)
        if build == 'B':
            compile_alternative(root, root / 'ServiceHost.swift', target / base.BINARY, runner)
        before_sign = (target / base.BINARY).read_bytes()
        runner(['/usr/bin/codesign', '--force', '--sign', base.SIGNER, '--timestamp=none',
                '--requirements', str(root / 'requirements.txt'), str(target)])
        base.verify_signature(target, runner)
        after_sign = (target / base.BINARY).read_bytes()
        # Preserve the existing copy-only equality for A. A freshly compiled B
        # may need a larger signature allocation; never normalize A to allow it.
        check(text_section(before_sign) == text_section(after_sign), 'Signing changed executable text')
        if build == 'A':
            check(base.code_payload(original_code) == base.code_payload(after_sign), 'A differs from installed host')
        inventories[build] = base.tree(target)
        text_hashes[build] = base.sha(text_section(after_sign))
    check(text_hashes['A'] == base.sha(original_text) and text_hashes['A'] != text_hashes['B'],
          'Alternative optimization did not change executable text')
    check(base.tree(app) == original, 'Original drift during prepare')
    check((root / 'ServiceHost.swift').read_bytes() == swift and
          (SOURCE / 'ServiceHost.swift').read_bytes() == swift, 'Frozen source drift')
    plan.update(configs=configs, builds=inventories, text_sha256=text_hashes,
                source_sha256=base.sha(swift), launcher_sha256=base.sha(launcher))
    # Seal immutable per-case inputs; mutable outputs never enter this inventory.
    plan['sealed'] = sealed
    durable(root, 'prepared.json', plan)
    return plan


def load_plan(root):
    install, _ = base.helpers()
    root = install.safe(root)
    p = read_json(root / 'prepared.json')
    check(p['schema'] == 1 and p['root'] == str(root)
          and root.parent == Path(p['home']) / '.hermes/experiments'
          and p['requirement'] == base.REQUIREMENT and p['name'] in NAMES
          and p['matrix'] == [list(v) for v in MATRIX]
          and re.fullmatch(r'com\.charles\.verity\.continuity\.[0-9a-f]{32}', p['label']), 'Foreign plan')
    install.safe(Path(p['home']))
    install.safe(Path(p['base']))
    check(len(p['configs']) == len(MATRIX), 'Wrong case count')
    for i, (_, role, abi) in enumerate(MATRIX):
        c = p['configs'][i]
        check(c['root'] == str(case_dir(root, i)) and c['home'] == p['home'] and c['role'] == role
              and c['abi'] == [int(v) for v in abi.split('.')]
              and c['mode'] == 'permissions-check' and c['name'] == p['name'], 'Foreign case')
    return p


def preflight(root, runner=None):
    root = Path(root)
    p = load_plan(root)
    _, stage = base.helpers()
    verify_inputs(root, p)
    check((root / 'production_launcher.py').read_bytes() == launcher_source(root, p['configs']), 'Launcher drift')
    check(base.sha(Path(p['bootstrap']).read_bytes()) == p['bootstrap_sha256'], 'Bootstrap drift')
    for i, (_, role, _) in enumerate(MATRIX):
        case = case_dir(root, i)
        check((case / 'production_launcher.py').read_bytes() == worker_source(p['configs'][i]), 'Worker launcher drift')
        check((case / 'agent.plist').read_bytes() == plistlib.dumps(
            definition(case, Path(p['home']), p['label'] + f'.{i:02d}', role)), 'Job drift')
    for build in ('A', 'B'):
        app = root / 'builds' / (build + '.app')
        check(base.tree(app) == p['builds'][build], 'Build drift')
        check((app / base.SETTINGS).read_bytes() == stage.encoded(settings(root, p['bootstrap'], p['launcher_sha256'])),
              'Settings drift')
        check((app / 'Contents/Info.plist').read_bytes() == plistlib.dumps(stage.production_info_plist()), 'Metadata drift')
        check(base.sha(text_section((app / base.BINARY).read_bytes())) == p['text_sha256'][build], 'Text drift')
        base.verify_signature(app, runner)
    check(p['text_sha256']['A'] != p['text_sha256']['B'], 'No code change')
    return p


def events(case):
    path = case / 'agent.out'
    if not path.exists():
        return []
    check(not path.is_symlink() and path.stat().st_size < 65536, 'Unsafe output')
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    check(len(rows) <= 8 and all(type(r) is dict for r in rows), 'Unexpected output')
    schemas = {
        'service-host': {'event', 'pid', 'ppid', 'pgid', 'child_pid', 'guard_pid', 'role'},
        'supervisor-ready': {'event', 'pid', 'ppid', 'pgid', 'worker'},
        'worker-ready': {'event', 'pid', 'ppid', 'pgid', 'nonce'},
        'worker-complete': {'event', 'exit_code', 'results'},
        'supervisor-exit': {'event', 'exit_code'},
        'service-exit': {'event', 'child_pid', 'status'},
        'host-refused': {'event', 'error_type'},
        'spawn-error': {'event', 'errno'},
    }
    for r in rows:
        check(r.get('event') in schemas and set(r) == schemas[r['event']], 'Unknown event/schema')
        if r['event'] == 'host-refused':
            check(type(r['error_type']) is str and
                  re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]{0,127}', r['error_type']), 'Invalid error type')
        if r['event'] == 'spawn-error':
            check(type(r['errno']) is int and 0 < r['errno'] <= 2147483647, 'Invalid spawn errno')
    check(len({r['event'] for r in rows}) == len(rows), 'Repeated event')
    return rows


def unique(rows, event):
    values = [r for r in rows if r.get('event') == event]
    check(len(values) <= 1, 'Duplicate event')
    return values[0] if values else None


def target(p, i):
    return f'gui/{os.getuid()}/' + p['label'] + f'.{i:02d}'


def identity(case, root, p, i, adapter, since):
    rows = events(case)
    check(not any(r['event'] in ('host-refused', 'spawn-error') for r in rows), 'Host failed')
    h, s, w = [unique(rows, e) for e in ('service-host', 'supervisor-ready', 'worker-ready')]
    if any(r is None for r in (h, s, w)):
        return False
    role = MATRIX[i][1]
    check(set(w) == {'event', 'pid', 'ppid', 'pgid', 'nonce'}
          and re.fullmatch('[0-9a-f]{48}', w['nonce']), 'Bad worker nonce')
    ids = [h['pid'], h['child_pid'], h['guard_pid'], w['pid']]
    check(all(type(v) is int and v > 1 for v in ids) and len(set(ids)) == 4, 'Aliased chain')
    check(h['role'] == role and h['ppid'] == 1 and h['pid'] == h['pgid'] == w['pgid'] == s['pgid']
          and h['child_pid'] == s['pid'] == w['ppid'] and s['ppid'] == h['pid']
          and s['worker'] == w['pid'] and adapter.job_pid(target(p, i)) == h['pid'], 'Wrong chain/job')
    exe = str(Path(p['home']) / 'Applications/Verity.app' / base.BINARY)
    python = p['bootstrap']
    worker = str(case / 'permission-python')
    expected = [(h['pid'], 1, exe, [exe, role]),
                (s['pid'], h['pid'], python, [python, '-I', '-B', str(root / 'production_launcher.py'),
                                             role, '--manifest', str(root / 'production-release.json')]),
                (w['pid'], s['pid'], worker, [worker, '-S', '-s', '-P', '-u', '-B',
                                             str(case / 'production_launcher.py'), '--worker'])]
    first = {}
    for pid, parent, executable, argv in expected:
        r = adapter.process(pid)
        check(r['pid'] == pid and r['ppid'] == parent and r['uid'] == os.getuid()
              and r['executable'] == executable and r['argv'] == argv, 'Kernel chain mismatch')
        first[pid] = r
    guard = adapter.process(h['guard_pid'])
    check(guard['pid'] == h['guard_pid'] and guard['ppid'] == h['pid'] and guard['uid'] == os.getuid()
          and guard['executable'] == exe and len(guard['argv']) == 4
          and guard['argv'][:2] == [exe, '--group-guard']
          and all(v.isdecimal() for v in guard['argv'][2:]), 'Guard mismatch')
    first[guard['pid']] = guard
    for pid, r in first.items():
        birth = r['start_time']
        check(type(birth) in (int, float) and math.isfinite(birth) and since <= birth <= time.time() + 5
              and adapter.group(pid) == h['pid'], 'Bad birth/group')
        check(birth >= first[h['pid']]['start_time'], 'Child predates host')
    check(first[w['pid']]['start_time'] >= first[s['pid']]['start_time'], 'Worker predates supervisor')
    check(adapter.running_signature(h['pid']) is True, 'Running signer mismatch')
    check(all(adapter.process(pid) == r and adapter.group(pid) == h['pid']
              for pid, r in first.items()), 'Identity raced')
    return w


def artifact_absent(root, p, adapter):
    # Independent census, including failure before the first service-host event.
    ids, groups = set(), set()
    for i in range(len(MATRIX)):
        for r in events(case_dir(root, i)):
            if r.get('event') == 'service-host':
                ids.update(r[k] for k in ('pid', 'child_pid', 'guard_pid'))
                groups.add(r['pgid'])
            elif r.get('event') == 'worker-ready':
                ids.add(r['pid'])
                groups.add(r['pgid'])
            elif r.get('event') == 'supervisor-ready':
                ids.update((r['pid'], r['worker']))
                groups.add(r['pgid'])
    census = adapter.census()
    if ids.intersection(census) or any(g in groups for _, g in census.values()):
        return False
    app = Path(p['home']) / 'Applications/Verity.app'
    for pid, (uid, _) in census.items():
        if uid != os.getuid():
            continue
        try:
            r = adapter.process(pid)
        except Exception:
            if pid not in adapter.census():
                continue
            return False
        check(r['pid'] == pid and r['uid'] == uid, 'Census identity mismatch')
        exe = Path(r['executable'])
        if exe.is_relative_to(app) or exe.is_relative_to(root):
            return False
        if any(arg == str(root / 'production_launcher.py') or
               arg in {str(case_dir(root, i) / 'production_launcher.py') for i in range(len(MATRIX))}
               for arg in r['argv']):
            return False
    return True


class Live(base.Live):
    def job_pid(self, name):
        result = self.command('print', name)
        m = re.search(r'^\s*pid = (\d+)$', result.stdout, re.M)
        check(result.returncode == 0 and m is not None, 'Job PID unavailable')
        return int(m[1])

    def process(self, pid):
        return base.kernel_identity(pid)

    def group(self, pid):
        return os.getpgid(pid)

    def census(self):
        return base.process_census()

    def running_signature(self, pid):
        from native_identity import verify_signature
        return verify_signature(pid, base.REQUIREMENT)

    def clean(self, name):
        try:
            self.command('bootout', '--wait', name)
        except (OSError, subprocess.SubprocessError):
            pass
        base.wait(lambda: self.absent(name), 20)


def cleanup(root, p, adapter):
    # Intents, not events, define cleanup ownership. Never depend on legacy uptime.
    # One unknown earlier target must not prevent attempting the current target.
    known = True
    for i in range(len(MATRIX)):
        case = case_dir(root, i)
        try:
            if (case / 'intent.json').exists():
                intent = read_json(case / 'intent.json')
                check(set(intent) == {'target', 'index', 'since'} and intent['index'] == i
                      and intent['target'] == target(p, i), 'Foreign intent')
                adapter.clean(target(p, i))
            check(adapter.absent(target(p, i)) is True, 'Job absence unknown')
        except Exception:
            known = False
    check(known, 'Experiment cleanup incomplete')
    base.wait(lambda: artifact_absent(root, p, adapter), 20)


def restore(root, p, runner):
    app = Path(p['home']) / 'Applications/Verity.app'
    original = root / 'original.app'
    if original.exists():
        check(base.tree(original) == p['original'], 'Saved original drift')
        base.verify_signature(original, runner)
        if app.exists():
            current = base.tree(app)
            builds = [b for b in ('A', 'B') if current == p['builds'][b]]
            check(len(builds) == 1, 'Foreign final path')
            base.move(app, root / 'builds' / (builds[0] + '.app'))
        base.move(original, app)
    check(base.tree(app) == p['original'], 'Original restoration mismatch')
    base.verify_signature(app, runner)


def strict_results(rows, name):
    check(type(rows) is list and len(rows) == (2 if name == 'Accessibility' else 1), 'Wrong result count')
    result = base.sanitize(rows, name)
    check(len(result) == len(rows) and {r['name'] for r in result} ==
          ({name, 'Accessibility Finder role'} if name == 'Accessibility' else {name}), 'Wrong result names')
    check(all(r['requested'] is False and r['error_type'] is None for r in result), 'Not check-only completion')
    # Status/allowed agreement is required, not just a truthy allowed field.
    statuses = {'Full Disk Access: Messages': {'opened_read_only'},
                'Full Disk Access: Safari': {'opened_read_only'},
                'Calendar': {'full_access'}, 'Reminders': {'full_access'},
                'Accessibility Finder role': {0}, 'Automation: Finder': {'authorized'}}
    allowed = all(r['allowed'] is True and r['status'] in statuses.get(r['name'], {'authorized'}) for r in result)
    return result, allowed


def report_status(root, name):
    """Read a terminal decision, not an isolated provisional success report.

    Malformed/missing evidence refuses. Interrupts affect only their named report.
    """
    check(isinstance(name, str) and (name == 'result.json' or
          re.fullmatch(r'recovery-[0-9a-f]{32}\.json', name)), 'Invalid report name')
    root = Path(root)
    report = read_json(root / name)
    decision = read_json(root / ('settled-' + name))
    check(type(decision) is dict and set(decision) == {'report', 'status'}
          and decision['report'] == name and decision['status'] in ('completed', 'restored', 'failed'),
          'Malformed terminal decision')
    check(type(report) is dict and report.get('status') in ('completed', 'restored', 'failed'),
          'Malformed report')
    invalidated = False
    for path in root.glob('interrupt-*.json'):
        row = read_json(path)
        check(type(row) is dict and set(row) == {'status', 'interrupted', 'report'}
              and row['status'] == 'failed' and row['interrupted'] is True
              and isinstance(row['report'], str) and (row['report'] == 'result.json' or
              re.fullmatch(r'recovery-[0-9a-f]{32}\.json', row['report'])), 'Malformed invalidator')
        invalidated |= row['report'] == name
    if invalidated or decision['status'] == 'failed':
        return 'failed'
    check(decision['status'] == report['status'] and report.get('cleanup_verified') is True
          and report.get('restored') is True, 'Unsettled report')
    return decision['status']


class ReconciliationSignals:
    """Latch the first signal; execution checkpoints cancel, cleanup keeps going.

    Never raise the first signal asynchronously: it can land at any finally
    entry or rename boundary. Scope is the synchronous main-thread transaction.
    A late interrupt is retained separately because result receipts are immutable.
    """
    def __init__(self, root):
        self.root = root
        self.interrupted = False
        self.report: dict | None = None
        self.report_name = None
        self.previous = {}

    def __enter__(self):
        try:
            for sig in (signal.SIGINT, signal.SIGTERM):
                self.previous[sig] = signal.signal(sig, self.handle)
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def handle(self, *_):
        if self.interrupted:
            raise KeyboardInterrupt()
        self.interrupted = True
        if self.report is not None:
            self.report['status'] = 'failed'

    def __exit__(self, exc_type, *_):
        # Block only teardown, after the complete reconciliation pass. In this
        # synchronous main-thread transaction no other thread consumes signals.
        watched = {signal.SIGINT, signal.SIGTERM}
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, watched)
        try:
            for sig, handler in self.previous.items():
                # Installing SIG_IGN discards blocked pending signals on POSIX.
                # Defer that disposition until after the pending-set decision.
                if handler != signal.SIG_IGN:
                    signal.signal(sig, handler)
            # Exact settlement boundary: this pending-set observation. Callable
            # and default caller handlers are restored; ignored ones stay latched.
            # Later arrivals belong to the caller.
            pending = signal.sigpending() & (watched - previous_mask)
            for sig in pending:
                signal.sigwait({sig})
            if pending:
                self.handle()
            if self.report is not None and self.report_name is not None:
                if exc_type is not None:
                    self.report['status'] = 'failed'
                if self.interrupted:
                    self.report['status'] = 'failed'
                    durable(self.root, 'interrupt-' + uuid.uuid4().hex + '.json',
                            dict(status='failed', interrupted=True, report=self.report_name))
                # A report without this terminal decision is provisional, never
                # authoritative success (including failed invalidator writes).
                durable(self.root, 'settled-' + self.report_name,
                        dict(report=self.report_name, status=self.report['status']))
        finally:
            try:
                for sig, handler in self.previous.items():
                    if signal.getsignal(sig) != handler:
                        signal.signal(sig, handler)
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def run(root, *, live=False, runner=None, adapter=None, dependency=None):
    check(live is True, 'Explicit --live required')
    root = Path(root)
    p = preflight(root, runner)
    install, _ = base.helpers()
    maintenance = Path(p['base'])
    install.safe(maintenance / 'control.lock')
    adapter = adapter or Live()
    dependency = dependency or install.no_live_native_dependency
    with install.control_lock(maintenance), ReconciliationSignals(root) as interrupts:
        old, saved = base.baseline(maintenance)
        base.unchanged(maintenance, old, saved, dependency)
        app = Path(p['home']) / 'Applications/Verity.app'
        check(base.tree(app) == p['original'], 'Installed original drift')
        base.verify_signature(app, runner)
        check(not (root / 'swap-receipt.json').exists() and not (root / 'original.app').exists(), 'Recover instead')
        for i in range(len(MATRIX)):
            check(adapter.absent(target(p, i)) is True, 'Existing job')
            check(not any((case_dir(root, i) / n).exists() for n in ('intent.json', 'GO', 'agent.out', 'result.json')),
                  'Previously used case')
        check(artifact_absent(root, p, adapter) is True, 'Existing artifact users or unknown identity')
        durable(root, 'swap-receipt.json', dict(plan=p, old=old, baseline=saved))
        report = dict(status='failed', cases=[], cleanup_verified=False, restored=False,
                      synthetic_roles_only=True, permission_authorization_is_not_task_authorization=True)
        interrupts.report = report
        try:
            check(not interrupts.interrupted, 'Interrupted admission')
            base.move(app, root / 'original.app')
            active = None
            for i, (build, _, _) in enumerate(MATRIX):
                check(not interrupts.interrupted, 'Interrupted execution')
                if build != active:
                    durable(root, f'swap-{i:02d}.json', {'from': active, 'to': build})
                    if active is not None:
                        check(base.tree(app) == p['builds'][active], 'Active build drift')
                        base.move(app, root / 'builds' / (active + '.app'))
                    base.move(root / 'builds' / (build + '.app'), app)
                    active = build
                check(base.tree(app) == p['builds'][build], 'Final-path build drift')
                base.verify_signature(app, runner)
                base.unchanged(maintenance, old, saved, dependency)
                roots = verify_inputs(root, p)
                deadline = time.monotonic() + 20  # Worker waits 30s; supervisor waits 50s.
                case = case_dir(root, i)
                since = time.time() - 1
                durable(case, 'intent.json', dict(target=target(p, i), index=i, since=since))
                check(not interrupts.interrupted, 'Interrupted before bootstrap')
                check(time.monotonic() < deadline, 'Identity gate deadline')
                adapter.bootstrap(target(p, i), case)
                ready = base.wait(lambda: identity(case, root, p, i, adapter, since),
                                  max(0, deadline - time.monotonic()))
                verify_gate_inputs(root, p, i, roots, deadline)
                check({r['event'] for r in events(case)} ==
                      {'service-host', 'supervisor-ready', 'worker-ready'}, 'Premature completion')
                check(identity(case, root, p, i, adapter, since) == ready, 'Worker changed before GO')
                check(time.monotonic() < deadline, 'Identity gate deadline')
                check(not interrupts.interrupted, 'Interrupted before GO')
                durable(case, 'GO', ready)
                check(not interrupts.interrupted, 'Interrupted GO publication')
                complete = base.wait(lambda: unique(events(case), 'worker-complete'), 20)
                check(set(complete) == {'event', 'exit_code', 'results'} and type(complete['exit_code']) is int
                      and complete['exit_code'] == 0, 'Worker failed')
                results, allowed = strict_results(complete['results'], p['name'])
                supervisor = base.wait(lambda: unique(events(case), 'supervisor-exit'), 5)
                host = base.wait(lambda: unique(events(case), 'service-exit'), 5)
                check(type(supervisor['exit_code']) is int and supervisor['exit_code'] == 0
                      and type(host['status']) is int and host['status'] == 0
                      and host['child_pid'] == unique(events(case), 'service-host')['child_pid'], 'Unclean child exit')
                exited = base.wait(lambda: adapter.exited(dict(label=p['label'] + f'.{i:02d}')), 10)
                check(type(exited['exit_code']) is int and exited['exit_code'] == 0, 'Unclean host exit')
                check(not any(r['event'] in ('host-refused', 'spawn-error') for r in events(case)),
                      'Host failed after GO')
                cleanup(root, p, adapter)
                check(not interrupts.interrupted, 'Interrupted case cleanup')
                result = dict(index=i, build=build, role=MATRIX[i][1], abi=MATRIX[i][2], results=results,
                              status='allowed' if allowed else 'not_allowed', cleanup_verified=True)
                durable(case, 'result.json', result)
                report['cases'].append(result)
                check(allowed, 'Authorization continuity failed')
            report['status'] = 'failed' if interrupts.interrupted else 'completed'
        except BaseException:
            report['status'] = 'failed'
            for j in range(len(MATRIX)):
                failed_case = case_dir(root, j)
                if (failed_case / 'intent.json').exists() and not (failed_case / 'result.json').exists():
                    durable(failed_case, 'result.json', dict(index=j, status='failed'))
        finally:
            try:
                cleanup(root, p, adapter)
                report['cleanup_verified'] = True
                base.unchanged(maintenance, old, saved)
                restore(root, p, runner)
                report['restored'] = True
                base.unchanged(maintenance, old, saved)
            except BaseException:
                report['status'] = 'failed'
            interrupts.report_name = 'result.json'
            durable(root, interrupts.report_name, report)
        return report


def recover(root, *, live=False, runner=None, adapter=None):
    check(live is True, 'Explicit --live required')
    root = Path(root)
    p = load_plan(root)  # Never regenerate launchers or require both staged builds here.
    receipt = read_json(root / 'swap-receipt.json')
    check(receipt['plan'] == p, 'Recovery plan mismatch')
    install, _ = base.helpers()
    maintenance = Path(p['base'])
    install.safe(maintenance / 'control.lock')
    adapter = adapter or Live()
    with install.control_lock(maintenance), ReconciliationSignals(root) as interrupts:
        cleanup(root, p, adapter)
        check(base.baseline(maintenance) == (receipt['old'], receipt['baseline']), 'Recovery baseline drift')
        base.unchanged(maintenance, receipt['old'], receipt['baseline'])
        restore(root, p, runner)
        base.unchanged(maintenance, receipt['old'], receipt['baseline'])
        report = dict(status='failed' if interrupts.interrupted else 'restored', cleanup_verified=True, restored=True)
        interrupts.report = report
        interrupts.report_name = 'recovery-' + uuid.uuid4().hex + '.json'
        durable(root, interrupts.report_name, report)
        return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('prepare', 'preflight', 'run', 'recover'))
    parser.add_argument('--root', type=Path, required=True)
    for name in ('base', 'home', 'python', 'runtime311', 'runtime314', 'bridge311', 'bridge314'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--permission', choices=NAMES)
    parser.add_argument('--approve-sign', action='store_true')
    parser.add_argument('--live', action='store_true')
    args = parser.parse_args(argv)
    if args.phase == 'prepare':
        if any(getattr(args, k) is None for k in ('base', 'home', 'python', 'runtime311', 'runtime314',
                                                'bridge311', 'bridge314', 'permission')):
            parser.error('All explicit preparation inputs are required')
        prepare(args.root, args.base, args.home, args.python,
                {'3.11': args.runtime311, '3.14': args.runtime314},
                {'3.11': args.bridge311, '3.14': args.bridge314}, args.permission,
                approve_sign=args.approve_sign)
        report = {'status': 'prepared_not_run'}
    elif args.phase == 'preflight':
        preflight(args.root)
        report = {'status': 'preflight_not_run'}
    else:
        report = (run if args.phase == 'run' else recover)(args.root, live=args.live)
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] in ('prepared_not_run', 'preflight_not_run', 'completed', 'restored') else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        print(json.dumps({'status': 'failed'}))
        raise SystemExit(1)
