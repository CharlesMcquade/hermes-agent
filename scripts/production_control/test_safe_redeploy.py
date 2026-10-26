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


REAL_VERIFY_BINDING = runner.verify_binding
REAL_VERIFY_AUTHORIZATION = runner.verify_authorization


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
        self.consumer = SimpleNamespace(Refused=type('Refused', (Exception,), {}),
                                        inspect_binding=Mock(return_value={'session_revision': 'rev'}))
        self.stack.enter_context(patch.object(runner.continuation, 'load_consumer', return_value=self.consumer))
        self.stack.enter_context(patch.object(runner.continuation, 'deployment_binding', return_value={}))
        self.stack.enter_context(patch.object(runner.continuation, 'initialize'))
        self.stack.enter_context(patch.object(runner.continuation, 'publish_request',
            side_effect=lambda *args, **kw: {'binding': kw['binding']}))
        self.stack.enter_context(patch.object(runner, 'verify_authorization'))
        self.stack.enter_context(patch.object(runner, 'verify_binding',
            return_value={'session_id': 's', 'profile': 'default', 'workspace': '/work'}))
        self.stack.enter_context(patch.object(runner.routing, 'profile_routing_guard', return_value=lambda: None))
        self.inspection = self.stack.enter_context(patch.object(runner, 'initial_inspection',
            return_value=(self.manifest, lambda: None, {})))
        self.state('session_settled', binding={'session_id': 's', 'profile': 'default', 'workspace': '/work'})

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

    def _real_binding_guards(self):
        """Swap the setUp mocks for the real verify_binding/verify_authorization."""
        self.stack.enter_context(patch.object(runner, 'verify_binding', REAL_VERIFY_BINDING))
        self.stack.enter_context(patch.object(runner, 'verify_authorization', REAL_VERIFY_AUTHORIZATION))
        binding = dict(session_id='s', profile='default', workspace='/work', model='m', model_provider='p',
                       session_revision='rev')
        self.current = dict(binding)
        self.consumer.inspect_binding = Mock(side_effect=lambda *a, **kw: dict(self.current))
        self.state('session_settled', binding=binding)
        self.plan['approval'] = {'expires_at': 10**12}
        self.plan['session'] = {'session_id': 's'}
        self.anchor = self.stack.enter_context(patch.object(runner.continuation, 'human_anchor', return_value='anchor'))

    def test_anchor_move_after_first_kick_reports_instead_of_aborting(self):
        """A3 regression: a human message after the WebUI signal must not abort or roll back."""
        self.terminal_fixture()
        self._real_binding_guards()
        def activation(c, pending, pin, checkpoint):
            checkpoint('before_kick', service='webui')
            # The user types in the session while WebUI restarts; the transcript moves.
            self.anchor.return_value = 'moved'
            self.current['session_revision'] = 'rev+1'
            checkpoint('before_kick', service='agent')
            return {'proof': {'process_identity': self.identity}}
        self.engine.run_activation.side_effect = activation
        with patch.object(runner.continuation, 'publish_terminal', return_value={'verified': True}) as publish, \
             patch.object(runner.continuation, 'receipt_status', return_value={'status': 'worker_entered', 'stream_id': 'x'}):
            self.assertEqual(self.execute()['outcome'], 'worker_entered')
        publish.assert_called_once()
        self.engine.rollback_pending.assert_not_called()

    def test_anchor_move_before_first_kick_still_refuses_and_rolls_back(self):
        self.terminal_fixture()
        self._real_binding_guards()
        def activation(c, pending, pin, checkpoint):
            self.anchor.return_value = 'moved'
            checkpoint('before_kick', service='webui')
            raise AssertionError('signal must not happen')
        self.engine.run_activation.side_effect = activation
        with patch.object(runner.continuation, 'publish_terminal') as publish:
            with self.assertRaisesRegex(RuntimeError, 'User intervened'):
                self.execute()
        publish.assert_not_called()
        # Rollback is itself anchor-fenced: the run stops with the selection
        # written and no process signalled, for independent review.
        self.engine.rollback_pending.assert_not_called()
        self.assertEqual(self.selected.read_bytes(), self.newraw)

    def test_failure_after_verified_activation_raises_without_rollback(self):
        self.terminal_fixture()
        with patch.object(runner.continuation, 'publish_terminal', side_effect=OSError('publisher down')):
            with self.assertRaisesRegex(OSError, 'publisher down'):
                self.execute()
        self.engine.rollback_pending.assert_not_called()
        self.assertEqual(self.state.value['outcome'], 'verified_unreported')

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
        self.assertEqual(resumed.value['binding'], {'session_id': 's', 'profile': 'default', 'workspace': '/work'})
        self.assertEqual((self.root / 'state.json.writing').read_text(), 'partial')

    def test_idle_bounded_wait_and_owner_validation(self):
        # The runtime aggregate remains authoritative even when drain detail is null.
        for change in ({'active_agents': 1, 'active_work': None}, {'active_agents': None},
                       {'active_agents': False}, {'active_work': {'other': 'task'}}):
            self.gateway(**change)
            with self.assertRaisesRegex(RuntimeError, 'active work'): runner.wait_idle(self.c, self.pending, 'pin', timeout=2)
        self.gateway(pid=999)
        with self.assertRaisesRegex(RuntimeError, 'owner mismatch'): runner.wait_idle(self.c, self.pending, 'pin', timeout=2)
        self.gateway(); runner.wait_idle(self.c, self.pending, 'pin', timeout=12)

    def test_diagnostic_report_cannot_authorize_nonzero_gateway_work(self):
        report = self.root / 'diagnosis.md'; report.write_bytes(b'unknown whether stale')
        self.plan['gateway_active_agents_advisory'] = {
            'observed_agents': 1, 'gateway_pid': 123,
            'report_path': str(report), 'report_sha256': runner.sha(report.read_bytes())}
        self.gateway(active_agents=1, active_work=None)
        with self.assertRaisesRegex(RuntimeError, 'Unproven gateway idle override refused'):
            self.execute()
        self.pending.prepare.assert_not_called()
        self.pending.select.assert_not_called()
        self.engine.run_activation.assert_not_called()
        self.engine.rollback_pending.assert_not_called()
        with self.assertRaisesRegex(RuntimeError, 'active work'):
            runner.wait_idle(self.c, self.pending, 'pin', timeout=2)

    def test_binding_probe_requires_settled_revision_before_authorization(self):
        self.gateway()
        runner.wait_idle(self.c, self.pending, 'pin', timeout=14, binding_probe=lambda: 'rev')
        with self.assertRaisesRegex(RuntimeError, 'active work'):
            runner.wait_idle(self.c, self.pending, 'pin', timeout=4, binding_probe=lambda: None)
        flip = iter(['a', 'b', 'a', 'b'])
        with self.assertRaisesRegex(RuntimeError, 'active work'):
            runner.wait_idle(self.c, self.pending, 'pin', timeout=4, binding_probe=lambda: next(flip, 'z'))

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

    def test_settled_binding_is_refreshed_before_immutable_publication(self):
        self.terminal_fixture()
        fresh = {'session_id': 's', 'session_revision': 'new'}
        events = []
        def verify(consumer, plan, binding, *, exact=False, authorize=True):
            events.append('exact' if exact else 'refresh')
            if exact:
                self.assertEqual(binding, fresh)
            return fresh
        def publish(*args, **kw):
            events.append('publish')
            self.assertEqual(kw['binding'], fresh)
            self.assertGreaterEqual(self.now, 10)
            return {'binding': dict(kw['binding'])}
        with patch.object(runner, 'verify_binding', side_effect=verify), \
             patch.object(runner.continuation, 'publish_request', side_effect=publish), \
             patch.object(runner.continuation, 'publish_terminal', return_value={}), \
             patch.object(runner.continuation, 'receipt_status', return_value={'status': 'worker_entered', 'stream_id': 'stream'}):
            self.execute()
        self.assertEqual(events[:3], ['refresh', 'publish', 'exact'])
        self.assertEqual(self.state.value['request']['binding'], fresh)

    def test_published_revision_change_refuses_selection(self):
        self.prepared()
        def verify(consumer, plan, binding, *, exact=False, authorize=True):
            if exact:
                raise RuntimeError('Published session revision changed')
            return binding
        with patch.object(runner, 'verify_binding', side_effect=verify):
            with self.assertRaisesRegex(RuntimeError, 'Published session revision'):
                self.execute()
        self.pending.select.assert_not_called()
        self.engine.run_activation.assert_not_called()

    def test_existing_request_is_never_rebound_to_checkpoint(self):
        self.prepared()
        pinned = {'session_id': 's', 'session_revision': 'published'}
        self.state('resume_request_published', request={'binding': pinned})
        with patch.object(runner, 'verify_binding', side_effect=RuntimeError('stop')) as verify, \
             patch.object(runner.continuation, 'publish_request') as publish:
            with self.assertRaisesRegex(RuntimeError, 'stop'):
                self.execute()
        publish.assert_not_called()
        self.assertEqual(verify.call_args.args[2], pinned)
        self.assertTrue(verify.call_args.kwargs['exact'])
        self.pending.select.assert_not_called()

    def test_busy_observation_resets_ten_second_window(self):
        def health(*args):
            return {'status': 'ok', 'active_runs': int(self.now == 5), 'active_streams': 0}
        self.c.health.side_effect = health
        runner.wait_idle(self.c, self.pending, 'pin', timeout=18)
        self.assertEqual(self.now, 16)

    def test_intervention_during_wait_aborts_without_waiting_for_timeout(self):
        def guard():
            if self.now == 3:
                raise RuntimeError('User intervened')
        with self.assertRaisesRegex(RuntimeError, 'User intervened'):
            runner.wait_idle(self.c, self.pending, 'pin', timeout=60, guard=guard)
        self.assertEqual(self.now, 3)

    def test_intervention_at_service_edge_refuses_action(self):
        guard = Mock(side_effect=RuntimeError('User intervened'))
        guarded = runner.idle_checkpoint(self.c, self.pending, 'pin', lambda *a, **kw: None, guard=guard)
        with self.assertRaisesRegex(RuntimeError, 'User intervened'):
            guarded('before_kick', service='agent')
        guard.assert_called_once()


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.binding = dict(session_id='s', profile='default', workspace='/work',
                            model='model', model_provider='provider', session_revision='old')
        self.current = dict(self.binding, session_revision='new')
        self.consumer = SimpleNamespace(inspect_binding=Mock(side_effect=lambda *a, **kw: dict(self.current)))
        self.plan: dict = dict(session={'session_id': 's'}, session_dir='/state/webui', state_home='/state',
                         human_anchor='anchor', approval={'expires_at': 200})
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(runner.time, 'time', return_value=100))
        self.anchor = self.stack.enter_context(patch.object(runner.continuation, 'human_anchor', return_value='anchor'))

    def test_refresh_accepts_only_same_identity_before_publication(self):
        self.assertEqual(runner.verify_binding(self.consumer, self.plan, self.binding), self.current)
        self.current['model'] = 'other'
        with self.assertRaisesRegex(RuntimeError, 'identity changed'):
            runner.verify_binding(self.consumer, self.plan, self.binding)

    def test_exact_postpublication_revision_refuses_even_identity_equal(self):
        with self.assertRaisesRegex(RuntimeError, 'Published session revision changed'):
            runner.verify_binding(self.consumer, self.plan, self.binding, exact=True)
        self.current = dict(self.binding)
        self.assertEqual(runner.verify_binding(self.consumer, self.plan, self.binding, exact=True), self.binding)

    def test_human_intervention_and_expiry_remain_fail_closed(self):
        self.anchor.return_value = 'different'
        with self.assertRaisesRegex(RuntimeError, 'User intervened'):
            runner.verify_binding(self.consumer, self.plan, self.binding)
        self.consumer.inspect_binding.assert_not_called()
        self.anchor.return_value = 'anchor'
        self.plan['approval']['expires_at'] = 99
        with self.assertRaisesRegex(RuntimeError, 'approval expired'):
            runner.verify_binding(self.consumer, self.plan, self.binding)


if __name__ == '__main__': unittest.main()
