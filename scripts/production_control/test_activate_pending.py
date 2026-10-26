"""Exercise the activator entry point without installed controls or live jobs."""
import io
import json
import sys
import tempfile
import unittest
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import activate_pending as activator


class ActivatePendingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.pin = activator.digest(b'authorized pending receipt')
        self.now = 1000.0
        self.locked = False
        self.events = []
        self.publications = []
        self.candidate = set()
        self.fail_service = None
        self.c = Mock()
        self.c.manifest_path = self.base / 'production-release.json'
        self.c.manifest_path.write_bytes(b'candidate')
        self.c.retained_file.return_value = (b'candidate', None)
        self.c.loaded.return_value = {'webui': {'pid': 11}, 'agent': {'pid': 22}}
        self.c.target.side_effect = lambda manifest, service: 'job-' + service
        self.c.host.kickstart.side_effect = self.kick
        self.c.locked.side_effect = self.lock
        self.pending = SimpleNamespace(
            RESULT='pending-result.json',
            load=Mock(return_value=({'deadline': 2000, 'new': 'encoded'}, {}, {}, None)),
            decode=Mock(return_value=b'candidate'),
        )
        self.rp = SimpleNamespace(Controller=Mock(return_value=self.c))

    @contextmanager
    def lock(self):
        self.locked = True
        try:
            yield
        finally:
            self.locked = False

    def kick(self, label):
        self.events.append(label)
        if label.startswith('job-'):
            self.assertTrue(self.locked)
            service = label.removeprefix('job-')
            if service == self.fail_service:
                raise RuntimeError('service restart failed')
            self.candidate.add(service)

    def sleep(self, seconds):
        self.now += seconds
        self.assertFalse(self.locked)
        if self.publications:
            result = self.publications.pop(0)
            if result is not None:
                (self.base / self.pending.RESULT).write_text(json.dumps(result))

    def result(self, pin=None, status='verified'):
        return {'status': status, 'receipt_sha256': self.pin if pin is None else pin}

    def run_main(self, authorized=True):
        argv = ['activate_pending', '--base', str(self.base), '--controls', str(self.base),
                '--control-refresh-sha256', 'fixture-refresh-pin', '--settle-timeout', '36']
        if authorized:
            argv += ['--pin', self.pin]
        output = io.StringIO()
        with patch.object(sys, 'argv', argv), \
                patch.object(activator, 'prehash_bundle', return_value={}), \
                patch.object(activator, 'installed_modules', return_value=self.modules()), \
                patch.object(activator, 'find_child_pid', side_effect=lambda c, m, s, p: p + 100 if s in self.candidate else None), \
                patch.object(activator.time, 'time', side_effect=lambda: self.now), \
                patch.object(activator.time, 'sleep', side_effect=self.sleep), \
                redirect_stdout(output):
            code = activator.main()
        return code, json.loads(output.getvalue().splitlines()[-1])

    @contextmanager
    def modules(self):
        yield self.rp, self.pending

    def test_natural_publication_requires_exact_receipt_and_ordered_restarts(self):
        # A stale verified result and a current transition must not settle this run.
        self.publications = [self.result(self.pin + '0'), self.result(status='transition'), self.result()]
        code, report = self.run_main()
        self.assertEqual(code, 0)
        self.assertEqual(report['settlement'], self.result())
        self.assertEqual(self.publications, [])
        self.assertEqual(self.events, ['job-webui', 'job-agent'])
        self.pending.load.assert_called_once_with(self.c, self.pin)
        self.c.listener_ownership.assert_called_once()
        self.c.health.assert_called_once()

    def test_timeout_never_forces_watchdog_or_accepts_other_receipt(self):
        self.publications = [self.result('other-receipt')]
        code, report = self.run_main()
        self.assertEqual(code, 1)
        self.assertEqual(report['status'], 'settle_timeout')
        self.assertEqual(report['last_result'], self.result('other-receipt'))
        self.assertEqual(self.now, 1036)
        self.assertEqual(self.events, ['job-webui', 'job-agent'])

    def test_missing_result_times_out_without_watchdog_kicks(self):
        code, report = self.run_main()
        self.assertEqual(code, 1)
        self.assertIsNone(report['last_result'])
        self.assertEqual(self.events, ['job-webui', 'job-agent'])

    def test_already_candidate_services_wait_without_any_kicks(self):
        self.candidate.update(('webui', 'agent'))
        self.publications = [None, self.result()]
        code, report = self.run_main()
        self.assertEqual(code, 0)
        self.assertTrue(report['webui_skipped_kick'])
        self.assertTrue(report['agent_skipped_kick'])
        self.assertEqual(self.events, [])

    def test_restart_failure_stops_before_gateway_or_settlement(self):
        self.fail_service = 'webui'
        with self.assertRaisesRegex(RuntimeError, 'service restart failed'):
            self.run_main()
        self.assertEqual(self.events, ['job-webui'])
        self.assertEqual(self.now, 1000)
        self.c.rollback.assert_not_called()

    def test_authorization_pin_is_required_before_any_controller_action(self):
        with redirect_stdout(io.StringIO()), patch('sys.stderr', new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as raised:
                self.run_main(authorized=False)
        self.assertEqual(raised.exception.code, 2)
        self.rp.Controller.assert_not_called()
        self.assertEqual(self.events, [])


if __name__ == '__main__':
    unittest.main()
