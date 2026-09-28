"""Hermetic exact baseline return; no host calls or application imports."""
import base64
import hashlib
import json
import os
import plistlib
from pathlib import Path
import unittest
from unittest.mock import patch

import restart_production as control
import test_native_migration as fixtures


def digest(data):
    return hashlib.sha256(data).hexdigest()


class ReturnBaselineTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.NativeMigrationTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.c, self.host, self.base = self.f.c, self.f.host, self.f.base
        self.f.old['release_id'] = 'retained-legacy'
        control.save_json(self.c.manifest_path, self.f.old)
        self.original = b'\n ' + self.c.manifest_path.read_bytes() + b'\n'
        self.c.manifest_path.write_bytes(self.original)
        self.legacy = self.f.saved()
        self.version = self.base / 'control-versions/return-v1'
        self.version.mkdir(parents=True)
        hashes = {}
        for name in ('restart_production.py', 'approved_restart_job.py',
                     'production_launcher.py', 'native_identity.py', 'watchdog.py'):
            p = self.version / name
            p.write_bytes(b'isolated control fixture ' + name.encode())
            p.chmod(0o444)
            hashes[name] = digest(p.read_bytes())
        control.save_json(self.version / 'control-receipt.json', hashes)
        (self.version / 'control-receipt.json').chmod(0o444)
        self.version.chmod(0o555)
        self.baseline = {}
        for p in (self.c.manifest_path, *self.f.plists.values()):
            p.chmod(0o600)
            self.baseline[str(p)] = dict(data=base64.b64encode(p.read_bytes()).decode(),
                                        mode=0o600, uid=os.getuid())
        wrappers = {}
        replacements = {}
        for name in ('production_launcher.py', 'restart_production.py', 'watchdog.py', 'approved_restart_job.py'):
            path = self.base / name
            if not path.exists():
                path.write_bytes(b'fixture wrapper ' + name.encode())
            path.chmod(0o755)
            wrappers[name] = dict(data=base64.b64encode(b'original wrapper').decode(), mode=0o755, uid=os.getuid())
            replacements[name] = base64.b64encode(path.read_bytes()).decode()
        self.receipt = dict(wrappers=wrappers, replacements=replacements,
                            base=str(self.base), home=str(Path.home()), phase='installed',
                            baseline=self.baseline, report=dict(
                                status='staged_not_activated', activation_ready=False,
                                selected_sha256=digest(self.original),
                                candidate_sha256=digest((json.dumps(self.f.new, indent=2, sort_keys=True) + '\n').encode()),
                                rollback_sha256={**{r + '.plist': dict(sha256=digest(b), executable=False)
                                                    for r, b in self.legacy.items()},
                                                 **{'maintenance/' + n: dict(sha256=digest(b'original wrapper'), executable=False)
                                                    for n in wrappers}},
                                final_base=str(self.base), final_control_version=str(self.version),
                                final_bundle=self.f.new['native_host']['bundle'],
                                control_sha256=hashes))
        self.receipt_path = self.base / 'native-install-receipt.json'
        self.seal()
        self.assertEqual(self.f.activate()['status'], 'verified')
        self.artifacts = {p: (p.read_bytes(), p.stat().st_mode, p.stat().st_uid)
                          for directory in (Path(self.f.new['native_host']['bundle']), self.version)
                          for p in directory.rglob('*') if p.is_file()}
        self.artifacts.update({self.base / n: ((self.base / n).read_bytes(),
                                               (self.base / n).stat().st_mode,
                                               (self.base / n).stat().st_uid)
                               for n in wrappers})
        self.c.manifest_path.write_bytes(b'\n' + self.c.manifest_path.read_bytes() + b'  \n')
        for path in self.f.plists.values():
            path.write_bytes(plistlib.dumps(plistlib.loads(path.read_bytes()), fmt=plistlib.FMT_BINARY))
        self.native = self.c.manifest_path.read_bytes(), self.f.saved()
        (self.base / 'control.lock').chmod(0o600)
        for target in ('subprocess.run', 'subprocess.Popen'):
            guard = patch(target, side_effect=AssertionError('host call forbidden'))
            guard.start()
            self.addCleanup(guard.stop)
        guard = patch.object(control, '__file__', str(self.version / 'restart_production.py'))
        guard.start()
        self.addCleanup(guard.stop)

    def seal(self):
        payload = (json.dumps(self.receipt, indent=2, sort_keys=True) + '\n').encode()
        control.save_json(self.receipt_path, dict(schema_version=1, receipt=self.receipt,
                                                 sha256=digest(payload)))
        self.expected = digest(self.receipt_path.read_bytes())

    def assert_artifacts(self):
        for path, expected in self.artifacts.items():
            self.assertEqual((path.read_bytes(), path.stat().st_mode, path.stat().st_uid), expected)

    def run_return(self, **kwargs):
        return self.c.restart(reload=True, yes=True, return_baseline=self.expected, **kwargs)

    def test_exact_return_uses_new_native_fallback_and_keeps_receipt(self):
        receipt = self.receipt_path.read_bytes()
        self.assertEqual(self.run_return()['status'], 'verified')
        self.assertEqual((self.c.manifest_path.read_bytes(), self.f.saved()),
                         (self.original, self.legacy))
        txn = self.c.read_transaction()
        assert txn is not None
        self.assertEqual(txn['operation'], 'return-retained-baseline')
        self.assertEqual(base64.b64decode(txn['manifest']), self.native[0])
        self.assertEqual({r: base64.b64decode(b) for r, b in txn['plists'].items()}, self.native[1])
        self.assertEqual(self.receipt_path.read_bytes(), receipt)
        self.assert_artifacts()
        self.c.snapshot(self.c.load(), self.c.definitions(self.c.load()))


    def test_wrapper_drift_refuses_before_publication(self):
        (self.base / 'watchdog.py').write_bytes(b'foreign wrapper')
        before = self.c.transaction_path.read_bytes()
        calls = list(self.host.calls)
        with self.assertRaises(control.ControlError):
            self.run_return()
        self.assertEqual(self.c.transaction_path.read_bytes(), before)
        self.assertEqual(self.host.calls, calls)
        self.assertEqual((self.c.manifest_path.read_bytes(), self.f.saved()), self.native)


    def test_prepublication_race_after_journal_refuses(self):
        save = self.c.save_transaction
        calls = list(self.host.calls)

        def raced(txn, phase):
            save(txn, phase)
            if phase == 'prepared':
                self.receipt_path.write_bytes(b'changed after preparation')

        with patch.object(self.c, 'save_transaction', side_effect=raced):
            with self.assertRaises(control.ControlError):
                self.run_return()
        self.assertEqual((self.c.manifest_path.read_bytes(), self.f.saved()), self.native)
        self.assertEqual(self.host.calls, calls)


    def test_faults_recover_exact_native_once_without_consuming_baseline(self):
        class PowerLoss(BaseException):
            pass

        # Preparation, three publications, and both reload boundaries; failures
        # before and after rename are distinct atomic-write outcomes.
        for boundary in ('prepared', 'manifest', 'agent', 'webui', 'reload-agent', 'reload-webui'):
            for after in (False, True):
                with self.subTest(boundary=boundary, after=after):
                    if boundary != 'prepared' or after:
                        self.setUp()
                    receipt = self.receipt_path.read_bytes()
                    write, reload_job = control.atomic_write, self.host.reload
                    fired = False

                    def interrupt(path, data):
                        nonlocal fired
                        targets = {'prepared': self.c.transaction_path, 'manifest': self.c.manifest_path,
                                   **self.f.plists}
                        hit = not fired and path == targets.get(boundary)
                        if hit:
                            fired = True
                            if not after:
                                raise PowerLoss()
                        write(path, data)
                        if hit:
                            raise PowerLoss()

                    def interrupt_reload(target, path):
                        nonlocal fired
                        hit = not fired and boundary == 'reload-' + next(r for r, p in self.f.plists.items() if p == path)
                        if hit:
                            fired = True
                            if not after:
                                raise PowerLoss()
                        reload_job(target, path)
                        if hit:
                            raise PowerLoss()

                    with patch.object(control, 'atomic_write', side_effect=interrupt), patch.object(
                            self.host, 'reload', side_effect=interrupt_reload):
                        with self.assertRaises(PowerLoss):
                            self.run_return()
                    self.assertTrue(fired)
                    with control.control_lock(self.base):
                        result = self.c.recover_locked()
                    if boundary == 'prepared' and not after:
                        self.assertIsNone(result)
                    else:
                        self.assertEqual(result['status'], 'rolled_back')
                    self.assertEqual((self.c.manifest_path.read_bytes(), self.f.saved()), self.native)
                    calls = list(self.host.calls)
                    with control.control_lock(self.base):
                        self.assertIsNone(self.c.recover_locked())
                    self.assertEqual(self.host.calls, calls)
                    self.assertEqual(self.receipt_path.read_bytes(), receipt)
                    self.assert_artifacts()

    def test_failed_inverse_and_failed_fallback_are_bounded(self):
        for fallback_fails in (False, True):
            if fallback_fails:
                self.setUp()
            first = self.host.kicks + 1
            self.host.fail_kicks = {first, first + 1} if fallback_fails else {first}
            result = self.run_return()
            self.assertEqual(result['status'], 'rollback_failed' if fallback_fails else 'rolled_back')
            self.assertEqual((self.c.manifest_path.read_bytes(), self.f.saved()), self.native)
            calls = list(self.host.calls)
            if fallback_fails:
                with control.control_lock(self.base), self.assertRaises(control.ControlError):
                    self.c.recover_locked()
            else:
                with control.control_lock(self.base):
                    self.assertIsNone(self.c.recover_locked())
            self.assertEqual(self.host.calls, calls)

    def test_bad_provenance_and_inputs_refuse_without_destructive_actions(self):
        cases = ('digest', 'checksum', 'phase', 'base', 'home', 'version', 'control', 'wrapper',
                 'uid', 'mode', 'missing-plist', 'label', 'state', 'plist-label', 'alias',
                 'revoked-id', 'revoked-content', 'policy', 'symlink', 'unsafe-mode',
                 'lock', 'lock-symlink', 'pending', 'failed', 'preflight', 'not-native',
                 'current-drift', 'output-symlink')
        for index, case in enumerate(cases):
            with self.subTest(case=case):
                if index:
                    self.setUp()
                if case in ('phase', 'base', 'home'):
                    self.receipt[case] = 'foreign'
                elif case == 'version':
                    self.receipt['report']['final_control_version'] = str(self.base / 'foreign')
                elif case == 'control':
                    self.receipt['report']['control_sha256']['watchdog.py'] = '0' * 64
                elif case == 'wrapper':
                    self.receipt['replacements']['watchdog.py'] = base64.b64encode(b'foreign').decode()
                elif case in ('uid', 'mode'):
                    self.baseline[str(self.c.manifest_path)][case] = -1 if case == 'uid' else 0o666
                elif case == 'missing-plist':
                    del self.baseline[str(self.f.plists['agent'])]
                elif case in ('label', 'state', 'alias'):
                    old = json.loads(self.original)
                    if case == 'label':
                        old['labels']['agent'] = 'foreign'
                    elif case == 'state':
                        old['state_dir'] += '/foreign'
                    else:
                        old['services']['agent']['plist_path'] = str(self.c.manifest_path)
                    self.baseline[str(self.c.manifest_path)]['data'] = base64.b64encode(json.dumps(old).encode()).decode()
                elif case == 'plist-label':
                    self.baseline[str(self.f.plists['agent'])]['data'] = base64.b64encode(b'not a plist').decode()
                self.seal()
                if case == 'digest':
                    self.expected = '0' * 64
                elif case == 'checksum':
                    envelope = json.loads(self.receipt_path.read_bytes())
                    envelope['sha256'] = '0' * 64
                    control.save_json(self.receipt_path, envelope)
                    self.expected = digest(self.receipt_path.read_bytes())
                elif case.startswith('revoked') or case == 'policy':
                    policy = dict(schema_version=1, release_ids=[], content_digests=[])
                    if case == 'revoked-id':
                        policy['release_ids'] = [self.f.old['release_id']]
                    elif case == 'revoked-content':
                        policy['content_digests'] = [self.c.content_digest(self.f.old)]
                    else:
                        policy = {'invalid': True}
                    control.save_json(self.base / 'revoked-releases.json', policy)
                elif case in ('symlink', 'lock-symlink', 'output-symlink'):
                    path = self.receipt_path if case == 'symlink' else self.base / (
                        'control.lock' if case == 'lock-symlink' else 'restart-journal.jsonl')
                    target = self.base / 'linked'
                    path.rename(target)
                    path.symlink_to(target)
                elif case == 'unsafe-mode':
                    self.receipt_path.chmod(0o666)
                elif case in ('pending', 'failed'):
                    self.c.save_transaction(self.c.read_transaction(), 'prepared' if case == 'pending' else 'rollback_failed')
                elif case == 'preflight':
                    self.c.preflight_fn = lambda m: (_ for _ in ()).throw(control.ControlError('preflight refused'))
                elif case == 'not-native':
                    self.c.manifest_path.write_bytes(self.original)
                elif case == 'current-drift':
                    self.f.plists['webui'].write_bytes(b'invalid current plist')
                before = self.c.manifest_path.read_bytes(), self.f.saved()
                txn = self.c.transaction_path.read_bytes()
                calls = list(self.host.calls)
                if case == 'lock':
                    with control.control_lock(self.base), self.assertRaises(control.ControlError):
                        self.run_return()
                else:
                    with self.assertRaises((control.ControlError, ValueError, KeyError, plistlib.InvalidFileException)):
                        self.run_return()
                self.assertEqual((self.c.manifest_path.read_bytes(), self.f.saved()), before)
                self.assertEqual(self.c.transaction_path.read_bytes(), txn)
                self.assertEqual(self.host.calls, calls)

    def test_approval_cli_and_incomplete_recovery_remain_distinct(self):
        import approved_restart_job as approved
        args = ['--base', str(self.base), '--restart', '--yes', '--reload', '--return-baseline', self.expected]
        with patch.object(approved, 'restart_main', return_value={'status': 'verified'}) as main:
            with self.assertRaises(control.ControlError):
                approved.main(args, owner=lambda: 42)
            main.assert_not_called()
            approved.main(args, owner=lambda: 1)
            main.assert_called_once_with(args)
        with patch.object(control, 'Controller') as factory:
            control.main(args)
            self.assertEqual(factory.return_value.restart.call_args.kwargs['return_baseline'], self.expected)
        for kwargs in (dict(reload=False, yes=True), dict(reload=True, yes=False),
                       dict(reload=True, yes=True, candidate=self.f.candidate)):
            with self.assertRaises(control.ControlError):
                self.c.restart(return_baseline=self.expected, **kwargs)
        self.c.owner = lambda: 42
        with self.assertRaises(control.ControlError):
            self.run_return()


    def test_stage_provenance_mismatch_refuses(self):
        for key in ('selected_sha256', 'candidate_sha256', 'rollback_sha256'):
            with self.subTest(key=key):
                if key != 'selected_sha256':
                    self.setUp()
                self.receipt['report'][key] = {} if key == 'rollback_sha256' else '0' * 64
                self.seal()
                calls = list(self.host.calls)
                with self.assertRaises((control.ControlError, KeyError)):
                    self.run_return()
                self.assertEqual((self.c.manifest_path.read_bytes(), self.f.saved()), self.native)
                self.assertEqual(self.host.calls, calls)


    def test_input_races_and_installed_modes_refuse_before_publication(self):
        cases = ('selection', 'plist', 'policy', 'lock', 'control', 'version-mode', 'receipt-mode')
        for index, case in enumerate(cases):
            with self.subTest(case=case):
                if index:
                    self.setUp()
                if case == 'version-mode':
                    self.version.chmod(0o755)
                elif case == 'receipt-mode':
                    (self.version / 'control-receipt.json').chmod(0o600)
                else:
                    old_preflight = self.c.preflight_fn
                    fired = False

                    def race(manifest):
                        nonlocal fired
                        old_preflight(manifest)
                        if fired:
                            return
                        fired = True
                        if case == 'policy':
                            control.save_json(self.base / 'revoked-releases.json',
                                              dict(schema_version=1, release_ids=[], content_digests=[]))
                        else:
                            path = {'selection': self.c.manifest_path, 'plist': self.f.plists['agent'],
                                    'lock': self.base / 'control.lock',
                                    'control': self.version / 'watchdog.py'}[case]
                            if case == 'control':
                                path.chmod(0o644)
                                path.write_bytes(path.read_bytes())
                                path.chmod(0o444)
                            else:
                                control.atomic_write(path, path.read_bytes())
                    self.c.preflight_fn = race
                calls = list(self.host.calls)
                transaction = self.c.transaction_path.read_bytes()
                with self.assertRaises(control.ControlError):
                    self.run_return()
                self.assertEqual(self.host.calls, calls)
                self.assertEqual((self.c.manifest_path.read_bytes(), self.f.saved()), self.native)
                self.assertEqual(self.c.transaction_path.read_bytes(), transaction)


if __name__ == '__main__':
    unittest.main()
