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
