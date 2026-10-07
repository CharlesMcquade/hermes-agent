"""Disposable adapter tests; process identities and writes are fixture-only."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('selection_adapter', ROOT/'select_for_user_restart.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
import test_pending_user_restart as fixture
import watchdog as pending


class AdapterTests(unittest.TestCase):
    def setUp(self):
        f = fixture.PendingTests(); f.setUp()
        self.addCleanup(f.doCleanups)
        self.f = f; self.c = f.c; self.base = f.base
        self.old_pin = s.digest(f.old); self.new_pin = s.digest(f.candidate.read_bytes())
        self.patches = [patch.object(s, 'OLD_PIN', self.old_pin), patch.object(s, 'NEW_PIN', self.new_pin)]
        for p in self.patches:
            p.start(); self.addCleanup(p.stop)

    def action(self, action, **kwargs):
        return s.run_protocol(self.c, pending, action, self.f.candidate,
                              self.old_pin, self.new_pin, **kwargs)

    def test_check_and_approval_boundaries_preserve_everything(self):
        (self.base/'control.lock').touch()  # Installed protocol requires a pre-existing lock.
        before = {p: p.read_bytes() for p in self.base.rglob('*') if p.is_file()}
        result = self.action('check')
        self.assertEqual(result['status'], 'checked_not_staged')
        for action in ('prepare', 'select'):
            with self.assertRaisesRegex(s.SelectionRefused, 'approval'):
                self.action(action)
        self.assertEqual(before, {p: p.read_bytes() for p in self.base.rglob('*') if p.is_file()})
        self.assertEqual(self.f.host.calls, [])

    def test_existing_protocol_prepare_select_keep_old_process_identities(self):
        before = copy.deepcopy(self.f.f.processes)
        prepared = self.action('prepare', approval=True)
        self.assertEqual(prepared['status'], 'prepared_not_selected')
        self.assertEqual(self.c.manifest_path.read_bytes(), self.f.old)
        pin = prepared['receipt_sha256']
        selected = self.action('select', approval=True, receipt_pin=pin)
        self.assertEqual(selected['status'], 'selected_awaiting_user_restart')
        self.assertEqual(self.c.manifest_path.read_bytes(), self.f.candidate.read_bytes())
        self.assertEqual(self.f.f.processes, before)
        self.assertEqual(self.f.host.calls, [])
        self.assertEqual(self.action('select', approval=True, receipt_pin=pin)['status'], 'already_selected')

    def test_altered_pending_proof_and_selector_cas_rejected(self):
        pin = self.action('prepare', approval=True)['receipt_sha256']
        path = self.base/pending.RECEIPT; raw = path.read_bytes()
        path.write_bytes(raw+b' ')
        with self.assertRaisesRegex(Exception, 'pin mismatch'):
            self.action('select', approval=True, receipt_pin=pin)
        path.write_bytes(raw)
        self.c.manifest_path.write_bytes(self.f.old+b' ')
        with self.assertRaisesRegex(Exception, 'CAS'):
            self.action('select', approval=True, receipt_pin=pin)
        self.assertEqual(self.f.host.calls, [])

    def test_guard_refuses_before_protocol_writes(self):
        def refuse(): raise s.SelectionRefused('routing proof changed')
        with self.assertRaisesRegex(s.SelectionRefused, 'routing proof changed'):
            self.action('prepare', approval=True, guard=refuse)
        self.assertFalse((self.base/pending.RECEIPT).exists())
        self.assertEqual(self.c.manifest_path.read_bytes(), self.f.old)

        # Exercise the public entry: unsafe profile routing must stop even
        # before installed Python is executed, not merely inside a helper test.
        home, runtime, new = ProfileRoutingTests.routing_fixture(self)
        (home / '.env').write_text('PATH=/synthetic-wrong\n')
        common = ['--base', str(self.base), '--controls', str(self.base/'controls'),
                  '--candidate', str(self.f.candidate), '--scratch', str(self.base),
                  '--control-refresh-sha256', s.REFRESH_PIN,
                  '--expect-selected-sha256', self.old_pin,
                  '--expect-candidate-sha256', self.new_pin]
        for flags in (['--check'], ['--prepare', '--approve-prepare'],
                      ['--select', '--approve-select', '--pending-receipt-sha256', '0'*64]):
            with patch.object(s, 'prehash_bundle', return_value=({}, lambda: None)), \
                 patch.object(s, 'manifest_inputs', return_value=({}, new)), \
                 patch.object(s, 'installed_modules', side_effect=AssertionError('must not import')) as imports, \
                 redirect_stdout(io.StringIO()) as out:
                self.assertEqual(s.main(common + flags), 2)
                imports.assert_not_called()
                self.assertNotIn('/synthetic-wrong', out.getvalue())

    def test_publication_edge_rechecks_adapter_proof(self):
        calls = []
        def guard():
            calls.append(True)
            if len(calls) == 3:
                raise s.SelectionRefused('proof altered before publication')
        s.bind_publication_guard(self.c, guard)
        with self.assertRaisesRegex(s.SelectionRefused, 'proof altered'):
            self.action('prepare', approval=True)
        self.assertFalse((self.base/pending.RECEIPT).exists())
        self.assertEqual(self.c.manifest_path.read_bytes(), self.f.old)
        self.assertEqual(self.f.host.calls, [])

    def test_candidate_and_old_pins_are_exact(self):
        with self.assertRaisesRegex(s.SelectionRefused, 'Unreviewed'):
            s.manifest_inputs(self.base, self.f.candidate, '0'*64, self.new_pin)
        self.f.candidate.write_bytes(self.f.candidate.read_bytes()+b' ')
        with self.assertRaisesRegex(s.SelectionRefused, 'Candidate.*CAS'):
            s.manifest_inputs(self.base, self.f.candidate, self.old_pin, self.new_pin)

    def test_unpinned_interpreter_blocks_before_any_candidate_execution(self):
        new = {'services': {'agent': {'repo': str(self.base/'agent')}, 'webui': {
            'repo': str(self.base/'webui'), 'argv': [str(self.base/'runtime/venv/bin/python')],
            'env_files': [str(self.base/'runtime.env')], 'env': {}}}}
        with patch.object(s.subprocess, 'run', side_effect=AssertionError('must not execute')):
            with self.assertRaisesRegex(s.SelectionRefused, 'does not pin HERMES_WEBUI_PYTHON'):
                s.prove_routes(new, self.base)

    def test_source_only_audit_never_claims_ready_or_old_button_safe(self):
        for release in ('old', 'new'):
            root = self.base/release
            (root/'api').mkdir(parents=True); (root/'hermes_cli').mkdir()
            for name in ('api/routes.py','api/gateway_restart.py','hermes_cli/gateway_launchd.py'):
                (root/name).write_text('fixture')
        def m(name): return {'services': {r: {'repo':str(self.base/name)} for r in ('webui','agent')}}
        result = s.audit_routes(m('old'),m('new'),self.base)
        self.assertEqual(result['status'],'pending_gate_not_checked')
        self.assertIn('unsafe',result['warning'])
        self.assertEqual(result['ordered_handoff'][0], 'Restart WebUI')




# AST-extracted verbatim from reviewed v5 api/profiles.py and native-v1 launcher.
# Execute only these source fragments, never candidate imports or real env files.
PROFILE_READER = '''def _read_active_profile_file() -> str:
    """Read the sticky active profile from ~/.hermes/active_profile."""
    ap_file = _DEFAULT_HERMES_HOME / 'active_profile'
    if ap_file.exists():
        try:
            name = ap_file.read_text(encoding="utf-8").strip()
            if name:
                return name
        except Exception:
            logger.debug("Failed to read active profile file")
    return 'default'
'''
NATIVE_ENTRY = '''import json,os,sys
item=json.loads(sys.argv[1])
if item.get("env_files"):
 from dotenv import dotenv_values
 for path in item["env_files"]:
  os.environ.update({k:v for k,v in dotenv_values(path,interpolate=False).items() if v is not None})
for name in ("PYTHONPATH","PYTHONHOME","PYTHONSTARTUP","_HERMES_GATEWAY"):
 os.environ.pop(name,None)
os.environ.update(item.get("env",{}))
os.environ["PYTHONDONTWRITEBYTECODE"]="1"
os.environ["PYTHONNOUSERSITE"]="1"
os.environ["PYTHONSAFEPATH"]="1"
os.chdir(item["cwd"])
os.execve(item["argv"][0],item["argv"],os.environ)
'''

class ProfileRoutingTests(unittest.TestCase):
    setUp = AdapterTests.setUp
    action = AdapterTests.action

    def routing_fixture(self):
        home = self.base / "profile-home"
        home.mkdir(exist_ok=True)
        (home / "active_profile").write_text("default\n")
        (home / ".env").write_text("TOKEN=synthetic-only\n")
        runtime = self.base / "runtime.env"
        runtime.write_text("TOKEN=synthetic-only\n")
        env = {"HERMES_HOME": str(home), "HERMES_BASE_HOME": str(home)}
        new = {"state_dir": str(home), "services": {
            "agent": {"repo": str(self.base / "agent"), "env": env.copy()},
            "webui": {"repo": str(self.base / "webui"), "env": env.copy(), "env_files": [str(runtime)]}}}
        return home, runtime, new

    def test_actual_absent_profile_defaults_and_appearance_is_fenced(self):
        import ast
        home, runtime, new = self.routing_fixture()
        (home / "active_profile").unlink()
        namespace = {"_DEFAULT_HERMES_HOME": home}
        exec(compile(ast.parse(PROFILE_READER), "v5-profile-reader", "exec"), namespace)
        self.assertEqual(namespace["_read_active_profile_file"](), "default")
        guard = s.profile_routing_guard(new)
        guard()
        self.assertFalse((home / "active_profile").exists())
        (home / "active_profile").write_text("default")
        with self.assertRaises(s.SelectionRefused): guard()

    def test_absent_profile_requires_safe_ancestry_and_exact_negative_existence(self):
        home, runtime, new = self.routing_fixture()
        active = home / "active_profile"
        active.unlink()
        guard = s.profile_routing_guard(new)
        active.symlink_to(home / "missing-target")
        with self.assertRaises(s.SelectionRefused): guard()
        with self.assertRaises(s.SelectionRefused): s.profile_routing_guard(new)
        active.unlink()
        home.chmod(0o777)
        try:
            with self.assertRaises(s.SelectionRefused): s.profile_routing_guard(new)
        finally:
            home.chmod(0o700)
        with patch.object(s.os, "stat", side_effect=PermissionError("synthetic")):
            with self.assertRaises(s.SelectionRefused): s.profile_routing_guard(new)
        identity = s.absent_profile_identity(active)
        home.rename(home.with_name("old-home"))
        home.mkdir()
        self.assertNotEqual(identity, s.absent_profile_identity(active))

    def test_absent_profile_appearance_blocks_both_publication_edges(self):
        home, runtime, new = self.routing_fixture()
        active = home / "active_profile"
        active.unlink()
        for action in ("prepare", "select"):
            if action == "select":
                receipt = self.action("prepare", approval=True)["receipt_sha256"]
            guard = s.profile_routing_guard(new)
            original = self.c.refresh_admission
            calls = []
            def appear():
                calls.append(True)
                if len(calls) == 3:
                    active.write_text("default")
                guard()
            s.bind_publication_guard(self.c, appear)
            kwargs = {"approval": True}
            if action == "select": kwargs["receipt_pin"] = receipt
            with self.assertRaises(s.SelectionRefused): self.action(action, **kwargs)
            self.assertEqual(self.c.manifest_path.read_bytes(), self.f.old)
            if action == "prepare": self.assertFalse((self.base/pending.RECEIPT).exists())
            self.assertEqual(self.f.host.calls, [])
            self.c.refresh_admission = original
            active.unlink()

    def test_actual_native_entry_supersedes_only_startup_assignments(self):
        import ast
        import sys
        import types
        tree = ast.parse((ROOT / "production_launcher.py").read_text())
        actual_entry = next(ast.literal_eval(n.value) for n in tree.body
                            if isinstance(n, ast.Assign) and any(
                                isinstance(a, ast.Name) and a.id == "_ENTRY" for a in n.targets))
        self.assertEqual(actual_entry, NATIVE_ENTRY)
        home, runtime, new = self.routing_fixture()
        env = new["services"]["webui"]["env"]
        env["HERMES_WEBUI_AGENT_DIR"] = str(self.base / "agent")
        values = {"HERMES_HOME": "/synthetic-wrong", "HERMES_WEBUI_AGENT_DIR": "/synthetic-wrong",
                  **{key: "/synthetic-wrong" for key in s.STARTUP_SUPERSEDED}}
        runtime.write_text("".join(k+"="+v+"\n" for k,v in values.items()))
        # Real launcher AST; only credential parser and process boundary are synthetic.
        dotenv = types.ModuleType("dotenv")
        def parse(path, *, interpolate):
            self.assertIs(interpolate, False)
            self.assertEqual(path, str(runtime))
            return dict(line.split("=", 1) for line in runtime.read_text().splitlines())
        dotenv.dotenv_values = parse
        item = dict(new["services"]["webui"], cwd=str(self.base), argv=["/synthetic-python"])
        with patch.dict(os.environ, {}, clear=True), patch.dict(sys.modules, {"dotenv": dotenv}), \
             patch.object(sys, "argv", ["entry", json.dumps(item)]), \
             patch.object(os, "chdir"), patch.object(os, "execve") as execute:
            exec(compile(ast.parse(NATIVE_ENTRY), "native-v1-entry", "exec"), {})
            launched = dict(execute.call_args.args[2])
        self.assertEqual(launched["HERMES_HOME"], str(home))
        self.assertEqual(launched["HERMES_WEBUI_AGENT_DIR"], env["HERMES_WEBUI_AGENT_DIR"])
        for key in s.STARTUP_SUPERSEDED:
            if key in {"PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE", "PYTHONSAFEPATH"}:
                self.assertEqual(launched[key], "1")
            else:
                self.assertNotIn(key, launched)
        guard = s.profile_routing_guard(new)
        guard()
        runtime.write_text(runtime.read_text()+"# drift\n")
        with self.assertRaises(s.SelectionRefused): guard()
        # A shared startup file is safe only for the intersection of its readers.
        new["services"]["agent"]["env_files"] = [str(runtime)]
        with self.assertRaises(s.SelectionRefused): s.profile_routing_guard(new)
        new["services"]["agent"]["env"]["HERMES_WEBUI_AGENT_DIR"] = env["HERMES_WEBUI_AGENT_DIR"]
        s.profile_routing_guard(new)()
        # Aliasing a late loader never inherits the startup exemption.
        for late in (home / ".env", home / ".op.env", self.base / "webui/.env"):
            late.parent.mkdir(exist_ok=True)
            late.write_text("HERMES_HOME=/synthetic-wrong\n")
            new["services"]["webui"]["env_files"].append(str(late))
            with self.assertRaises(s.SelectionRefused): s.profile_routing_guard(new)
            late.write_text("TOKEN=synthetic-only\n")

    def test_routing_authority_is_default_only_and_values_never_escape(self):
        home, runtime, new = self.routing_fixture()
        s.profile_routing_guard(new)()
        for name in ("active_profile", ".env"):
            path = home / name; raw = path.read_bytes()
            path.unlink()
            if name == "active_profile":
                s.profile_routing_guard(new)()
            else:
                with self.assertRaises(s.SelectionRefused): s.profile_routing_guard(new)
            path.write_bytes(raw)
            path.chmod(0o666)
            with self.assertRaises(s.SelectionRefused): s.profile_routing_guard(new)
            path.chmod(0o600)
            path.unlink(); path.symlink_to(runtime)
            with self.assertRaises(s.SelectionRefused): s.profile_routing_guard(new)
            path.unlink(); path.write_bytes(raw)
        for profile in ("", "unknown", "Default", "../other"):
            (home / "active_profile").write_text(profile)
            with self.assertRaises(s.SelectionRefused): s.profile_routing_guard(new)
        (home / "active_profile").write_text("default\n")
        keys = ("PATH", "PYTHONPATH", "PYTHONHOME", "PYTHONUSERBASE", "VIRTUAL_ENV",
                "HOME", "HERMES_HOME", "HERMES_BASE_HOME", "HERMES_WEBUI_PYTHON",
                "HERMES_WEBUI_AGENT_DIR", "HERMES_AGENT_DIR", "HERMES_WEBUI_DIR",
                "HERMES_WEBUI_STATE_DIR", "HERMES_WEBUI_ISOLATED_PROFILE",
                "HERMES_CONFIG_PATH", "HERMES_PROFILE", "HERMES_ENV_PATH")
        for path in (home / ".env", runtime):
            for key in keys:
                for form in (key+"=synthetic-sensitive", "export "+key+"=synthetic-sensitive",
                             key+"=", "  "+key+" = \"synthetic-sensitive\""):
                    with self.subTest(key=key, form=form):
                        path.write_text(form+"\n")
                        if path == runtime and key in (s.STARTUP_SUPERSEDED | set(new["services"]["webui"]["env"])):
                            s.profile_routing_guard(new)()
                        else:
                            with self.assertRaises(s.SelectionRefused) as caught:
                                s.profile_routing_guard(new)
                            self.assertNotIn("synthetic-sensitive", str(caught.exception))
            for raw in (b"TOKEN=\xff", b"not an assignment", b"TOKEN=\"unterminated", b"TOKEN=ok\x00"):
                path.write_bytes(raw)
                with self.assertRaises(s.SelectionRefused): s.profile_routing_guard(new)
            path.write_text("TOKEN=synthetic-only\n")
        new["services"]["webui"]["env"]["HERMES_BASE_HOME"] = str(self.base / "unknown")
        with self.assertRaises(s.SelectionRefused): s.profile_routing_guard(new)

    def test_routing_drift_refuses_at_prepare_and_select_publication_edges(self):
        home, runtime, new = self.routing_fixture()
        for path in (home / "active_profile", home / ".env", runtime):
            guard = s.profile_routing_guard(new)
            raw = path.read_bytes(); path.write_bytes(raw + b"\n")
            with self.assertRaises(s.SelectionRefused): guard()
            path.write_bytes(raw)
        for path in (home / ".op.env", self.base / "agent/.env", self.base / "webui/.env"):
            guard = s.profile_routing_guard(new)
            path.parent.mkdir(exist_ok=True)
            path.write_text("PATH=/synthetic-wrong\n")
            with self.assertRaises(s.SelectionRefused): guard()
            with self.assertRaises(s.SelectionRefused): s.profile_routing_guard(new)
            path.unlink()
        for action in ("prepare", "select"):
            # Each iteration starts from a fresh disposable existing protocol.
            if action == "select":
                receipt = self.action("prepare", approval=True)["receipt_sha256"]
            guard = s.profile_routing_guard(new)
            original = self.c.refresh_admission
            calls = []
            def mutate_at_publication():
                calls.append(True)
                if len(calls) == 3:
                    (home / ".env").write_text("PATH=/synthetic-wrong\n")
                guard()
            s.bind_publication_guard(self.c, mutate_at_publication)
            kwargs = {"approval": True}
            if action == "select": kwargs["receipt_pin"] = receipt
            with self.assertRaises(s.SelectionRefused): self.action(action, **kwargs)
            self.assertEqual(self.c.manifest_path.read_bytes(), self.f.old)
            if action == "prepare": self.assertFalse((self.base/pending.RECEIPT).exists())
            self.assertEqual(self.f.host.calls, [])
            self.c.refresh_admission = original
            (home / ".env").write_text("TOKEN=synthetic-only\n")


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ['TMPDIR'])
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name); self.controls = self.base/'controls'; self.controls.mkdir()
        self.hashes = {}
        for name in s.MODULES:
            raw = b'raise AssertionError("must never import unapproved fixture")\n'
            (self.controls/(name+'.py')).write_bytes(raw)
            self.hashes[name+'.py'] = s.digest(raw)
        (self.controls/'control-receipt.json').write_text(json.dumps(self.hashes))
        self.receipt = self.base/'native-control-refresh-receipt.json'
        self.receipt.write_text(json.dumps({'stage':{'base':str(self.base),'version':str(self.controls),'control_sha256':self.hashes}}))
        self.pin = s.digest(self.receipt.read_bytes())

    def test_fake_self_pinned_bundle_is_not_authority(self):
        with self.assertRaisesRegex(s.SelectionRefused,'Unreviewed'):
            s.prehash_bundle(self.base,self.controls,self.pin)
        with self.assertRaisesRegex(s.SelectionRefused,'receipt pin mismatch'):
            s.prehash_bundle(self.base,self.controls,s.REFRESH_PIN)

    def test_every_module_and_receipt_prehashed_before_any_import(self):
        with patch.object(s,'REFRESH_PIN',self.pin):
            observations, unchanged = s.prehash_bundle(self.base,self.controls,self.pin)
            for name in s.MODULES:
                p=self.controls/(name+'.py'); raw=p.read_bytes(); p.write_bytes(raw+b'#tamper')
                with self.assertRaisesRegex(s.SelectionRefused,'Unpinned control module'):
                    s.prehash_bundle(self.base,self.controls,self.pin)
                p.write_bytes(raw)
            self.receipt.write_bytes(self.receipt.read_bytes()+b' ')
            with self.assertRaisesRegex(s.SelectionRefused,'proof changed'):
                unchanged()
            self.assertEqual(len(observations),8)

    def test_public_approval_checks_precede_bundle_import(self):
        common=['--base',str(self.base),'--controls',str(self.controls),'--candidate',str(self.base/'missing'),
                '--scratch',str(self.base),'--control-refresh-sha256',s.REFRESH_PIN,
                '--expect-selected-sha256',s.OLD_PIN,'--expect-candidate-sha256',s.NEW_PIN]
        for flags in (['--prepare'],['--select'],['--check','--approve-prepare'],['--select','--approve-select']):
            with patch.object(s,'prehash_bundle',side_effect=AssertionError('no bundle access')), redirect_stdout(io.StringIO()) as out:
                self.assertEqual(s.main(common+flags),2)
            self.assertNotIn('no bundle access',out.getvalue())


if __name__ == '__main__':
    unittest.main()
