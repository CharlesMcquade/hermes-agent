#!/usr/bin/env python3
"""Bounded adapter for the reviewed installed pending-user-restart protocol.

check is production-read-only (disposable routing fixtures are written to scratch).
prepare and select each require separate explicit approval; neither restarts.
Only the reviewed v5 transition is admitted. New bundles/releases require review.
"""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import types

REFRESH_PIN = 'ea590ad502cba1309d96ddc106f10a3072025426fe3be5c0e2d593e4eac6c18a'
OLD_PIN = '81e8bbbe26d629ee8137445d6334b04ccc9cc3597f088e5ff965debd712194f3'
NEW_PIN = '72fb5888fdf571d403412e5478897e79ae849f03313de358f35c7affd81c6629'
MODULES = ('production_launcher', 'restart_production', 'native_identity',
           'control_refresh', 'watchdog', 'approved_restart_job')
ORDER = ['Restart WebUI', 'Reconnect and verify candidate WebUI native identity',
         'Restart Gateway from the candidate WebUI, default profile only',
         'Read durable pending result and verify both candidate identities']
WARNING = 'Old WebUI Gateway control is unsafe: it can rewrite the native plist. Do not use it before the WebUI handoff.'


class SelectionRefused(RuntimeError):
    pass


def require(ok, message):
    if not ok:
        raise SelectionRefused(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def retained(path):
    path = Path(path)
    require(path.is_absolute() and path == path.resolve(), 'Noncanonical or symlink input')
    ancestry = []
    for ancestor in (path, *path.parents):
        st = ancestor.lstat()
        require(st.st_uid in {0, os.getuid()} and not st.st_mode & 0o7022,
                'Unsafe input owner/mode')
        require(stat.S_ISREG(st.st_mode) if ancestor == path else stat.S_ISDIR(st.st_mode),
                'Unsafe input type')
        ancestry.append((st.st_dev, st.st_ino, st.st_mode, st.st_uid))
    before = path.stat()
    require(before.st_size <= 64 * 1024 * 1024, 'Oversized input')
    raw = path.read_bytes()
    after = path.stat()
    require(before == after, 'Input changed during read')
    return raw, (tuple(ancestry), after.st_size, after.st_mtime_ns, after.st_ctime_ns)


# Finite routing surface of the reviewed launcher, WebUI profile reload and CLI.
# Reject even empty/shadowed assignments: no secret values or dotenv evaluation
# are needed to establish this deliberately narrower admission policy.
ROUTING_KEYS = frozenset({
    "PATH", "PYTHONPATH", "PYTHONHOME", "PYTHONUSERBASE", "PYTHONSTARTUP",
    "PYTHONEXECUTABLE", "PYTHONPLATLIBDIR", "PYTHONNOUSERSITE", "PYTHONSAFEPATH",
    "PYTHONDONTWRITEBYTECODE", "__PYVENV_LAUNCHER__", "VIRTUAL_ENV",
    "HOME", "USERPROFILE", "HERMES_HOME", "HERMES_BASE_HOME", "HERMES_PROFILE",
    "HERMES_CONFIG", "HERMES_CONFIG_PATH", "HERMES_ENV", "HERMES_ENV_PATH",
    "HERMES_WEBUI_PYTHON", "HERMES_WEBUI_AGENT_DIR", "HERMES_AGENT_DIR",
    "HERMES_WEBUI_DIR", "HERMES_WEBUI_STATE_DIR", "HERMES_WEBUI_ISOLATED_PROFILE",
    "DYLD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "DYLD_FRAMEWORK_PATH",
})
HANDOFF_PRECONDITION = (
    "Default profile only: no profile switches (including other clients), profile "
    "work, config/environment edits or supervisor-environment changes from check "
    "through both user restarts and identity verification. Otherwise stop and "
    "repeat admission; a completed check is not a launch-time fence."
)


def profile_routing_guard(new):
    """Read-only, invocation-local authority; never import real profile state.

    The WebUI reload is a line parser, unlike launcher python-dotenv. Admit only
    their unambiguous single-line assignment subset. Unsupported syntax is unknown,
    not safe. Retain hashes/identity only, never credentials in reports/fixtures.
    """
    try:
        home = Path(new["state_dir"])
        paths = {home / "active_profile", home / ".env"}
        optional = {home / ".op.env"}
        require(set(new["services"]) == {"agent", "webui"}, "Unknown services")
        for service in new["services"].values():
            env = service["env"]
            optional.add(Path(service["repo"]) / ".env")
            require(env.get("HERMES_HOME") == str(home)
                    and env.get("HERMES_BASE_HOME") == str(home),
                    "Unknown default-profile routing authority")
            paths.update(Path(p) for p in service.get("env_files", []))
        # Only canonical keys, optional export, and complete one-line values.
        assignment = re.compile(r'''(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(?:"(?:[^"\\\r\n]|\\.)*"|'(?:[^'\\\r\n]|\\.)*'|[^'"\r\n]*)(?:[ \t]*\#.*)?''')
        def observe():
            observations = {}
            for path in sorted(paths | optional):
                require(path.is_absolute() and path == path.resolve(), "Unknown routing path")
                if path in optional and not os.path.lexists(path):
                    observations[path] = None  # Known optional loader input; fence appearance.
                    continue
                raw, identity = retained(path)
                text = raw.decode("utf-8")
                require("\x00" not in text, "Unknown routing input syntax")
                if path == home / "active_profile":
                    require(text.strip() == "default", "Default profile authority required")
                else:
                    for line in text.splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        match = assignment.fullmatch(line)
                        require(match is not None, "Unknown routing input syntax")
                        require(match[1] not in ROUTING_KEYS,
                                "Routing override assignment refused")
                observations[path] = (digest(raw), identity)
            return observations
        initial = observe()
    except Exception:
        # Never propagate decode/parser errors that can quote credential content.
        raise SelectionRefused("Default-profile routing authority absent, unsafe or unsupported") from None
    def unchanged():
        try:
            require(observe() == initial, "Routing authority changed")
        except Exception:
            raise SelectionRefused("Default-profile routing authority changed or unsafe") from None
    unchanged()
    return unchanged


def prehash_bundle(base, controls, pin):
    """No installed Python executes before the complete pinned set is retained."""
    require(pin == REFRESH_PIN, 'Unreviewed control refresh pin')
    receipt_path = base / 'native-control-refresh-receipt.json'
    receipt = retained(receipt_path)
    require(digest(receipt[0]) == pin, 'Control refresh receipt pin mismatch')
    data = json.loads(receipt[0])
    stage = data['stage']
    require(stage['base'] == str(base) and stage['version'] == str(controls),
            'Wrong installed control bundle')
    hashes = stage['control_sha256']
    require(set(hashes) == {n + '.py' for n in MODULES}, 'Incomplete six-module authority')
    require(set(p.name for p in controls.iterdir()) == set(hashes) | {'control-receipt.json'},
            'Foreign control bundle membership')
    observations = {receipt_path: receipt}
    observations[controls / 'control-receipt.json'] = retained(controls / 'control-receipt.json')
    require(json.loads(observations[controls / 'control-receipt.json'][0]) == hashes,
            'Control bundle receipt mismatch')
    for name, checksum in hashes.items():
        path = controls / name
        observations[path] = retained(path)
        require(digest(observations[path][0]) == checksum, 'Unpinned control module: ' + name)
    def unchanged():
        for path, value in observations.items():
            require(retained(path) == value, 'Control proof changed: ' + str(path))
        require(set(p.name for p in controls.iterdir()) == set(hashes) | {'control-receipt.json'},
                'Control membership changed')
    unchanged()
    return observations, unchanged


@contextmanager
def installed_modules(controls, observations):
    require(not any(n in sys.modules for n in MODULES), 'Refuse preloaded control modules; use a fresh isolated CLI')
    try:
        for name in MODULES:
            module = types.ModuleType(name)
            module.__file__ = str(controls / (name + '.py'))
            sys.modules[name] = module
            # Execute precisely the bytes prehashed above, never a second path read or pyc.
            exec(compile(observations[Path(module.__file__)][0], module.__file__, 'exec'), module.__dict__)
        yield sys.modules['restart_production'], sys.modules['watchdog']
    finally:
        for name in MODULES:
            sys.modules.pop(name, None)


def manifest_inputs(base, candidate, old_pin, new_pin, pending_pin=None):
    require(old_pin == OLD_PIN and new_pin == NEW_PIN, 'Unreviewed old/new manifest pins')
    current = retained(base / 'production-release.json')
    new_raw = retained(candidate)[0]
    require(digest(new_raw) == new_pin, 'Candidate manifest CAS mismatch')
    old_raw = current[0]
    if pending_pin:
        require(re.fullmatch('[0-9a-f]{64}', pending_pin), 'Invalid pending receipt pin')
        raw = retained(base / 'pending-user-restart.json')[0]
        require(digest(raw) == pending_pin, 'Pending receipt pin mismatch')
        receipt = json.loads(raw)
        old_raw = base64.b64decode(receipt['old']['data'], validate=True)
        require(base64.b64decode(receipt['new']['data'], validate=True) == new_raw,
                'Pending candidate differs')
        require(current[0] in (old_raw, new_raw), 'Selected manifest CAS mismatch')
    require(digest(old_raw) == old_pin, 'Selected manifest CAS mismatch')
    return json.loads(old_raw), json.loads(new_raw)


def audit_routes(old, new, controls):
    """Source report only, separate from installed admission and dynamic proof."""
    paths = [Path(old['services']['agent']['repo']) / 'hermes_cli/gateway_launchd.py',
             Path(new['services']['webui']['repo']) / 'api/routes.py',
             Path(new['services']['webui']['repo']) / 'api/gateway_restart.py',
             Path(new['services']['agent']['repo']) / 'hermes_cli/gateway_launchd.py']
    return dict(status='pending_gate_not_checked', changed=False, warning=WARNING,
                ordered_handoff=ORDER, source_sha256={str(p): digest(p.read_bytes()) for p in paths})


# Actual candidate imports and CLI dispatch; only OS-service boundary is a fixture.
# This is not evidence of a real service restart, delivery, or live post-handoff state.
ROUTE_PROBE = r'''import json,sys,os,plistlib,subprocess,runpy
from pathlib import Path
from unittest.mock import patch
import api.config as config
import api.routes as routes
import api.gateway_restart as restart
import hermes_cli.gateway_launchd as launchd
import hermes_cli.gateway as gateway
agent,webui,python,console=map(Path,sys.argv[1:])
assert Path(config._AGENT_DIR)==agent
assert Path(config.PYTHON_EXE).resolve()==python.resolve()
assert Path(restart._resolve_hermes_command())==console
assert Path(launchd.__file__)==agent/'hermes_cli/gateway_launchd.py'
assert Path(gateway.__file__)==agent/'hermes_cli/gateway.py'
with patch.object(routes.subprocess,'run') as run:
 routes._run_gateway_lifecycle_command('restart')
 command=run.call_args.args[0]
 assert command==[config.PYTHON_EXE,str(agent/'hermes_cli/main.py'),'gateway','restart'],command
 assert run.call_args.kwargs['cwd']==str(agent)
 assert run.call_args.kwargs['env']['PYTHONPATH']==str(webui)+':'+str(agent)
 assert '_HERMES_GATEWAY' not in run.call_args.kwargs['env']
with patch.object(restart.subprocess,'Popen') as popen:
 popen.return_value.communicate.return_value=('','')
 popen.return_value.returncode=0
 assert restart.restart_active_profile_gateway(profile='default')['status']=='completed'
 assert popen.call_args.args[0]==[str(console),'--profile','default','gateway','restart']
home=Path(os.environ['HERMES_HOME']); plist=home/'gateway.plist'
definition={'Label':'ai.hermes.gateway','ProgramArguments':['/fixture/VerityServiceHost','agent'],'AssociatedBundleIdentifiers':['fixture.verity'],'EnvironmentVariables':{'HERMES_HOME':str(home)}}
raw=plistlib.dumps(definition); plist.write_bytes(raw)
commands=[]
def sink(cmd,**kwargs):
 if Path(cmd[0]).name=='git':
  return subprocess.CompletedProcess(cmd,1,'','')
 commands.append(cmd)
 if cmd[:2]==['launchctl','print']:
  if cmd[2].startswith('user/'): return subprocess.CompletedProcess(cmd,113,'','')
  out='\tpath = '+str(plist)+'\n\tprogram = /fixture/VerityServiceHost\n\targuments = {\n\t\t/fixture/VerityServiceHost\n\t\tagent\n\t}\n\tenvironment = {\n\t\tHERMES_HOME => '+str(home)+'\n\t}\n\tpid = 101\n'
  return subprocess.CompletedProcess(cmd,0,out,'')
 if cmd==['launchctl','kickstart','-k',f'gui/{os.getuid()}/ai.hermes.gateway']: return subprocess.CompletedProcess(cmd,0,'','')
 raise AssertionError('unexpected subprocess: '+repr(cmd))
with patch.object(gateway,'get_launchd_plist_path',return_value=plist),patch.object(gateway,'_wait_for_launchd_service_pid',return_value=True),patch.object(subprocess,'run',side_effect=sink),patch.object(gateway,'refresh_launchd_plist_if_needed',side_effect=AssertionError('unsafe refresh')),patch.object(sys,'argv',command[1:]):
 try:
  runpy.run_path(sys.argv[0],run_name='__main__')
 except SystemExit as exc:
  assert exc.code in (None,0),exc.code
assert commands==[['launchctl','print',f'gui/{os.getuid()}/ai.hermes.gateway'],['launchctl','print',f'user/{os.getuid()}/ai.hermes.gateway'],['launchctl','kickstart','-k',f'gui/{os.getuid()}/ai.hermes.gateway']],commands
assert plist.read_bytes()==raw
print('ROUTING_PROOF:'+json.dumps({'status':'candidate_native_route_proven','cli':str(agent/'hermes_cli/main.py'),'definition_preserved':True,'real_service_actions':False}))
'''


def prove_routes(new, scratch):
    helper = Path(__file__).with_name('candidate_canary.py')
    spec = importlib.util.spec_from_file_location('_routing_containment', helper)
    containment = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(containment)
    w = new['services']['webui']; a = Path(new['services']['agent']['repo'])
    webui = Path(w['repo']); python = Path(w['argv'][0]); runtime = python.parents[2]
    require(w['env'].get('HERMES_WEBUI_PYTHON') == str(python),
            'Candidate does not pin HERMES_WEBUI_PYTHON: inherited environment/runtime.env can override Gateway CLI interpreter; clean-fixture proof is insufficient')
    require(w['env']['PYTHONPATH'] == str(webui)+':'+str(a),
            'Unproven candidate import routing')
    require(w['env']['HERMES_WEBUI_AGENT_DIR'] == str(a), 'Wrong candidate agent override')
    require(Path(scratch).is_absolute() and Path(scratch) == Path(scratch).resolve(), 'Unsafe scratch')
    require(not any(Path(scratch).is_relative_to(p) or p.is_relative_to(Path(scratch))
                    for p in (a, webui, runtime)), 'Scratch overlaps candidate')
    with tempfile.TemporaryDirectory(prefix='pending-route-', dir=scratch) as temp:
        root = Path(temp)
        containment.initialize(root)
        home = root / 'home/.hermes'; home.mkdir()
        shutil.copyfile(root / 'state/config.yaml', home / 'config.yaml')
        env = containment.clean_env(root, a, webui, 0)
        env.update(HERMES_HOME=str(home), HERMES_BASE_HOME=str(home),
                   HERMES_CONFIG_PATH=str(home/'config.yaml'), PYTHONPATH=str(webui)+':'+str(a),
                   PATH=w['env']['PATH'], VIRTUAL_ENV=str(python.parents[1]),
                   HERMES_WEBUI_PYTHON=str(python))
        policy = containment.sandbox_policy(root, [a, webui, runtime], 0, [python, python.resolve()])
        policy = '\n'.join(line for line in policy.splitlines()
                           if 'network-bind' not in line and 'network-inbound' not in line)
        (root/'probe.sb').write_text(policy)
        (root/'probe.py').write_text(ROUTE_PROBE)
        result = subprocess.run(containment.cmd(root/'probe.sb', python, str(root/'probe.py'),
                                str(a), str(webui), str(python), str(python.parent/'hermes')),
                                cwd=root, env=env, capture_output=True, text=True, timeout=120)
        require(result.returncode == 0, 'Contained candidate routing proof failed (no stage authorized)')
        proofs = [line.removeprefix('ROUTING_PROOF:') for line in result.stdout.splitlines()
                  if line.startswith('ROUTING_PROOF:')]
        require(len(proofs) == 1, 'Missing or ambiguous candidate routing proof')
        proof = json.loads(proofs[0])
        require(proof == dict(status='candidate_native_route_proven', cli=str(a/'hermes_cli/main.py'),
                             definition_preserved=True, real_service_actions=False), 'Invalid routing proof')
        return proof


def bind_publication_guard(c, guard):
    """Add input admission at the existing controller's lock/publication edges."""
    original = c.refresh_admission
    def admission():
        guard()
        refresh = original()
        def unchanged():
            refresh()
            guard()
        unchanged()
        return unchanged
    c.refresh_admission = admission


def run_protocol(c, pending, action, candidate, old_pin, new_pin, *, approval=False,
                 receipt_pin=None, guard=lambda: None):
    """Delegate mutations only to watchdog's existing prepare/select transaction."""
    require(action in {'check', 'prepare', 'select'}, 'Invalid action')
    require(action == 'check' or approval is True, 'Explicit action-specific approval required')
    require(action != 'select' or receipt_pin is not None, 'Select requires prepared receipt pin')
    guard()
    if action == 'prepare':
        return pending.prepare(c, candidate, expected_old_sha256=old_pin, expected_new_sha256=new_pin)
    if action == 'select':
        return pending.select(c, receipt_pin)
    with c.locked():
        unchanged = c.refresh_admission()
        guard()
        old, new = manifest_inputs(c.base, candidate, old_pin, new_pin, receipt_pin)
        txn = c.read_transaction()
        require(txn is not None and txn['phase'] in {'verified', 'rolled_back'}, 'Nonterminal transaction')
        if receipt_pin:
            pending.load(c, receipt_pin)
        else:
            require(not os.path.lexists(c.base/pending.RECEIPT) and 'pending_restart_sha256' not in txn,
                    'Existing pending state requires its exact receipt pin')
        pending.compatible(c, old, new)
        for m in (old, new):
            c.check_revocation(m); c.preflight(m)
        snapshot = c.snapshot(old, c.definitions(old))
        require('process_identity' in snapshot, 'Missing old native identity')
        unchanged(); guard()
        return dict(status='checked_not_staged', changed=False, process_action='none',
                    old_process_identity=snapshot['process_identity'])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('base', 'controls', 'candidate', 'scratch'):
        parser.add_argument('--'+key, required=True, type=Path)
    parser.add_argument('--control-refresh-sha256', required=True)
    parser.add_argument('--expect-selected-sha256', required=True)
    parser.add_argument('--expect-candidate-sha256', required=True)
    group = parser.add_mutually_exclusive_group()
    for action in ('check', 'prepare', 'select'):
        group.add_argument('--'+action, action='store_true')
    parser.add_argument('--approve-prepare', action='store_true')
    parser.add_argument('--approve-select', action='store_true')
    parser.add_argument('--pending-receipt-sha256')
    args = parser.parse_args(argv)
    action = 'prepare' if args.prepare else 'select' if args.select else 'check'
    admission = 'not_checked'
    try:
        require(args.approve_prepare == (action == 'prepare') and args.approve_select == (action == 'select'),
                'Explicit action-specific approval required; check accepts no approval')
        require(action != 'prepare' or args.pending_receipt_sha256 is None, 'Prepare cannot reuse pending receipt')
        require(action != 'select' or args.pending_receipt_sha256 is not None, 'Select requires prepared receipt pin')
        observations, unchanged = prehash_bundle(args.base, args.controls, args.control_refresh_sha256)
        def manifest_guard():
            unchanged()
            return manifest_inputs(args.base, args.candidate, args.expect_selected_sha256,
                                   args.expect_candidate_sha256, args.pending_receipt_sha256)
        old, new = manifest_guard()
        profile_unchanged = profile_routing_guard(new)
        def inputs():
            profile_unchanged()
            return manifest_guard()
        with installed_modules(args.controls, observations) as (controller, pending):
            c = controller.Controller(args.base, control_refresh_sha256=args.control_refresh_sha256)
            with c.locked():
                refresh = c.refresh_admission()
                refresh(); unchanged()
            admission = 'reviewed_installed_protocol_admitted'
            # Full manifest inventories BEFORE any application imports.
            for m in (old, new):
                sys.modules['production_launcher'].validate('agent', m['services'])
                sys.modules['production_launcher'].validate('webui', m['services'])
            routing = prove_routes(new, args.scratch)
            bind_publication_guard(c, inputs)
            result = run_protocol(c, pending, action, args.candidate, args.expect_selected_sha256,
                                  args.expect_candidate_sha256, approval=action != 'check',
                                  receipt_pin=args.pending_receipt_sha256, guard=inputs)
            print(json.dumps(dict(pending_gate=result, routing=routing, app_canary='separate_gate_not_run',
                                  warning=WARNING, ordered_handoff=ORDER, handoff_precondition=HANDOFF_PRECONDITION), indent=2))
        return 0
    except Exception as exc:
        print(json.dumps(dict(status='blocked', changed=False if action == 'check' else None,
                              error=str(exc), installed_protocol=admission, app_canary='separate_gate_not_run',
                              warning=WARNING, ordered_handoff=ORDER, handoff_precondition=HANDOFF_PRECONDITION), indent=2))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
