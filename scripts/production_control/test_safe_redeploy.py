"""Offline orchestration: fake syscalls, real checkpoint persistence and engine composition."""
from contextlib import ExitStack, nullcontext
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import safe_redeploy as runner


class Crash(BaseException): pass


class OrchestratorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.state = runner.Checkpoint(self.root, 'plan')
        self.oldraw, self.newraw = b'{"release":"old"}', b'{"release":"new"}'
        self.selected = self.root / 'selected.json'; self.selected.write_bytes(self.oldraw)
        self.private = self.root / 'private'; self.private.mkdir()
        self.plan = dict(base=str(self.root), controls=str(self.root), operation_dir=str(self.root),
            control_refresh_sha256='refresh', continuation_dir=str(self.private), selected_sha256=runner.sha(self.oldraw),
            candidate_sha256=runner.sha(self.newraw), candidate=str(self.root / 'candidate'), operation_id='a'*32,
            resume_message='Resume', session={}, session_dir=str(self.root), state_home=str(self.root), human_anchor='anchor')
        self.record = {'old': {'sha256': self.plan['selected_sha256']},
                       'new': {'sha256': self.plan['candidate_sha256']}, 'operation_id': 'pending'}
        self.manifest = {'state_dir': str(self.root)}
        self.identity = {'agent': {'child': {'pid': 123}}, 'webui': {'child': {'pid': 234}}}
        self.c = Mock(base=self.root, manifest_path=self.selected)
        self.c.locked.side_effect = lambda: nullcontext()
        self.c.refresh_admission.return_value = lambda: None
        self.c.retained_file.side_effect = lambda path: (Path(path).read_bytes(), None)
        self.c.health.return_value = {'status': 'ok', 'active_runs': 0, 'active_streams': 0}
        self.c.snapshot.return_value = {'process_identity': self.identity}
        self.now = 0
        self.c.monotonic.side_effect = lambda: self.now
        self.c.sleep.side_effect = self.sleep
        self.gateway()
        self.pending = Mock(RECEIPT='pending.json', RESULT='result.json')
        self.pending.load.return_value = (self.record, self.manifest, self.manifest, lambda: None)
        self.pending.effective_pair.return_value = (self.manifest, {}, self.identity)
        self.pending.select.side_effect = lambda *a: self.selected.write_bytes(self.newraw)
        self.engine = SimpleNamespace(run_activation=Mock(side_effect=RuntimeError('activation stopped')),
                                      rollback_pending=Mock())
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(sys.modules, safe_pending_activation=self.engine))
        self.stack.enter_context(patch.object(runner.admission, 'prehash_bundle', return_value={}))
        self.stack.enter_context(patch.object(runner.admission, 'installed_modules',
            side_effect=lambda *a: nullcontext((SimpleNamespace(Controller=lambda *a, **k: self.c), self.pending))))
        self.stack.enter_context(patch.object(runner.continuation, 'load_consumer', return_value=object()))
        self.stack.enter_context(patch.object(runner.continuation, 'deployment_binding', return_value={}))
        self.stack.enter_context(patch.object(runner.continuation, 'initialize'))
        self.stack.enter_context(patch.object(runner.continuation, 'publish_request', return_value={'request': True}))
        self.stack.enter_context(patch.object(runner, 'verify_binding', return_value={'session_id': 's'}))
        self.stack.enter_context(patch.object(runner.routing, 'profile_routing_guard', return_value=lambda: None))
        self.inspection = self.stack.enter_context(patch.object(runner, 'initial_inspection',
            return_value=(self.manifest, lambda: None, {})))
        self.state('session_settled', binding={'session_id': 's'})

    def sleep(self, seconds): self.now += seconds

    def gateway(self, **changes):
        state = dict(pid=123, gateway_state='running', active_agents=0, active_work={})
        state.update(changes)
        (self.root / 'gateway_state.json').write_text(json.dumps(state))

    def prepared(self): self.state('prepared', pending_pin='pin', controller_operation_id='pending')

    def execute(self): return runner.execute(self.plan, {}, self.state)

    def terminal_fixture(self):
        self.prepared()
        self.engine.run_activation.side_effect = None
        self.engine.run_activation.return_value = {"proof": {"process_identity": self.identity}}
        (self.root / 'result.json').write_text(json.dumps({'status': 'verified', 'operation_id': 'pending',
            'receipt_sha256': 'pin', 'selected': 'new', 'process_identity': self.identity,
            'candidate_identity': self.identity}))

    def test_verified_path_publishes_and_requires_worker_entry(self):
        self.terminal_fixture()
        with patch.object(runner.continuation, 'publish_terminal', return_value={'verified': True}) as publish, \
             patch.object(runner.continuation, 'receipt_status', return_value={'status': 'worker_entered', 'stream_id': 'stream'}):
            self.assertEqual(self.execute()['outcome'], 'worker_entered')
        publish.assert_called_once(); self.engine.rollback_pending.assert_not_called()

    def test_terminal_publication_succeeds_then_raises_never_rolls_back(self):
        self.terminal_fixture()
        def interrupted(*a):
            (self.private / 'terminal.json').write_text('{}')
            raise OSError('fsync interrupted')
        with patch.object(runner.continuation, 'publish_terminal', side_effect=interrupted):
            self.assertEqual(self.execute()['outcome'], 'ambiguous')
        self.engine.rollback_pending.assert_not_called()

    def test_changed_terminal_owner_never_publishes(self):
        self.terminal_fixture()
        self.engine.run_activation.return_value = {'proof': {'process_identity': {}}}
        with patch.object(runner.continuation, 'publish_terminal') as publish:
            with self.assertRaisesRegex(RuntimeError, 'owner changed'): self.execute()
        publish.assert_not_called()

    def test_selection_write_then_failure_rolls_back(self):
        self.prepared()
        def fail(*a):
            self.selected.write_bytes(self.newraw)
            raise RuntimeError('readback failed')
        self.pending.select.side_effect = fail
        with self.assertRaisesRegex(RuntimeError, 'readback failed'): self.execute()
        self.engine.rollback_pending.assert_called_once()
        self.assertEqual(self.state.value['outcome'], 'rolled_back')
        self.engine.run_activation.assert_not_called()

    def test_selection_failure_before_write_does_not_signal(self):
        self.prepared(); self.pending.select.side_effect = RuntimeError('select failed')
        with self.assertRaisesRegex(RuntimeError, 'select failed'): self.execute()
        self.engine.rollback_pending.assert_not_called()
        self.assertEqual(self.state.value['outcome'], 'failed_before_selection')

    def test_terminal_on_disk_before_checkpoint_never_signals_or_loads_pending(self):
        self.prepared(); (self.private / 'terminal.json').write_text('{')
        self.assertEqual(self.execute()['outcome'], 'ambiguous')
        self.pending.load.assert_not_called(); self.pending.select.assert_not_called()
        self.engine.rollback_pending.assert_not_called(); self.engine.run_activation.assert_not_called()

    def test_preparation_published_before_checkpoint_resumes_not_reprepares(self):
        self.state('preparing'); (self.root / 'pending.json').write_text('receipt')
        with self.assertRaisesRegex(RuntimeError, 'activation stopped'): self.execute()
        self.inspection.assert_not_called(); self.pending.prepare.assert_not_called()
        self.assertEqual(self.state.value['pending_pin'], runner.sha(b'receipt'))
        self.assertTrue(self.pending.load.call_args_list[0].kwargs['allow_unfenced'])

    def test_foreign_preparation_refused_without_signals(self):
        self.state('preparing'); (self.root / 'pending.json').write_text('receipt')
        self.record['new']['sha256'] = 'foreign'
        with self.assertRaisesRegex(RuntimeError, 'Foreign preparation'): self.execute()
        self.pending.select.assert_not_called(); self.engine.rollback_pending.assert_not_called()

    def test_retirement_journal_resumes_before_inspecting_missing_receipt(self):
        self.plan['recovery_pending_sha256'] = 'old-pin'
        archive = self.root / 'previous-receipt'; archive.mkdir(); (archive / 'retirement.json').write_text('{}')
        import safe_pending_retirement
        with patch.object(safe_pending_retirement, 'retire') as retire:
            self.pending.prepare.return_value = {'receipt_sha256': 'new-pin'}
            with self.assertRaisesRegex(RuntimeError, 'activation stopped'): self.execute()
        retire.assert_called_once()
        self.assertIsNone(self.inspection.call_args.args[2]['recovery_pending_sha256'])
        self.assertEqual(self.engine.rollback_pending.call_count, 1)  # candidate failure only, not old recovery

    def test_recovered_checkpoint_does_not_repeat_baseline_rollback(self):
        self.plan['recovery_pending_sha256'] = 'old-pin'; self.state('baseline_recovered')
        self.pending.prepare.return_value = {'receipt_sha256': 'new-pin'}
        with self.assertRaisesRegex(RuntimeError, 'activation stopped'): self.execute()
        self.assertIsNone(self.inspection.call_args.args[2]['recovery_pending_sha256'])
        self.assertEqual(self.engine.rollback_pending.call_count, 1)

    def test_checkpoint_resumes_handles_and_ignores_stranded_temporary(self):
        self.prepared(); (self.root / 'state.json.writing').write_text('partial')
        resumed = runner.Checkpoint(self.root, 'plan'); resumed('other')
        self.assertEqual(resumed.value['pending_pin'], 'pin')
        self.assertEqual(resumed.value['binding'], {'session_id': 's'})
        self.assertEqual((self.root / 'state.json.writing').read_text(), 'partial')

    def test_idle_bounded_wait_and_owner_validation(self):
        # active_agents counts cached agents and does NOT gate; active_work does.
        self.gateway(active_agents=1)
        runner.wait_idle(self.c, self.pending, 'pin', timeout=12)
        for change in ({'active_work': {'other': 'task'}}, {'active_work': {'x': 1}}):
            self.gateway(**change)
            with self.assertRaisesRegex(RuntimeError, 'active work'): runner.wait_idle(self.c, self.pending, 'pin', timeout=2)
        self.gateway(pid=999)
        with self.assertRaisesRegex(RuntimeError, 'owner mismatch'): runner.wait_idle(self.c, self.pending, 'pin', timeout=2)
        self.gateway(); runner.wait_idle(self.c, self.pending, 'pin', timeout=12)

    def test_mixed_baseline_settlement_uses_effective_pair_not_old_release(self):
        runner.settlement_health(self.c, self.pending, 'old-pin', {'wrong': 'baseline'})
        self.c.health.assert_called_once_with(self.manifest)

    def test_webui_busy_also_blocks_and_work_at_checkpoint_refuses_signal(self):
        self.c.health.return_value['active_runs'] = 1
        with self.assertRaisesRegex(RuntimeError, 'active work'): runner.wait_idle(self.c, self.pending, 'pin', timeout=2)
        self.c.health.return_value['active_runs'] = 0
        guarded = runner.idle_checkpoint(self.c, self.pending, 'pin', lambda *a, **k: self.gateway(active_agents=1))
        with self.assertRaisesRegex(RuntimeError, 'Work appeared'): guarded('before_kick', service='agent')

    def test_busy_gateway_prevents_selection(self):
        self.prepared(); self.gateway(active_agents=1)
        with self.assertRaisesRegex(RuntimeError, 'active work'): self.execute()
        self.pending.select.assert_not_called(); self.engine.rollback_pending.assert_not_called()


if __name__ == '__main__': unittest.main()
