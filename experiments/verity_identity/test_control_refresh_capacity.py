"""Large, nonsecret real composition; run under the offline pre-import harness."""
import base64
import json
import copy
import plistlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import control_refresh
import install_production_native as original
import refresh_production_controls as refresh
import test_control_refresh_composition as composition


class CapacityTests(unittest.TestCase):
    def test_large_real_activation_return_and_restore(self):
        # Padding is valid service environment data before first staging; every
        # downstream hash/backup/receipt is produced by the actual implementation.
        stage = composition.ServiceFixture.stage
        def padded(f, **changes):
            f.manifest['services']['agent']['env']['FIXTURE_PADDING'] = 'x' * (6 * 1024 * 1024)
            return stage(f, **changes)
        f = composition.ControlRefreshCompositionTests()
        self.addCleanup(f.doCleanups)
        with patch.object(composition.ServiceFixture, 'stage', padded):
            try:
                f.setUp()
            except Exception as exc:
                self.fail('Large real refresh preparation/publication refused: ' + str(exc))
        for raw in (f.root_raw, f.original_transaction, f.native_path.read_bytes(), f.refresh_raw):
            self.assertGreater(len(raw), original.MAX_RECEIPT)
        root = json.loads(f.root_raw)['receipt']
        self.assertEqual(original.decode(root['baseline'][str(f.f.selected)]), f.f.selected_before)
        receipt = json.loads(f.refresh_raw)
        self.assertEqual(original.decode(receipt['original_transaction']), f.original_transaction)
        self.assertEqual(receipt['stage']['root_sha256'], f.root_pin)
        self.assertEqual(json.loads(f.original_transaction)['schema_version'], 1)
        with self.assertRaisesRegex(Exception, 'Oversized'):
            original.root_install(f.f.base, f.f.home, f.root_pin)
        with self.assertRaisesRegex(Exception, 'Oversized'):
            original.bounded_json(f.f.base / original.RECEIPT)
        f.activate()
        native_bytes = f.f.selected.read_bytes()
        self.assertEqual(f.return_exact()['status'], 'verified')
        proof = refresh.snapshot(f.c.transaction_path)
        txn = f.c.read_transaction()
        self.assertEqual(base64.b64decode(txn['manifest']), native_bytes)
        self.assertEqual(txn['baseline_sha256'], f.root_pin)
        self.assertEqual(txn['control_refresh_sha256'], f.refresh_pin)
        for role in ('agent', 'webui'):
            for defect in ('wrong_host', 'extra_argument', 'wrong_bundle'):
                with self.subTest(role=role, defect=defect):
                    bad = copy.deepcopy(txn)
                    definition = plistlib.loads(base64.b64decode(bad['plists'][role]))
                    if defect == 'wrong_host':
                        definition['ProgramArguments'][0] = '/wrong/host'
                    elif defect == 'extra_argument':
                        definition['ProgramArguments'].insert(1, 'extra')
                    else:
                        definition['AssociatedBundleIdentifiers'] = ['wrong.bundle']
                    bad['plists'][role] = base64.b64encode(plistlib.dumps(definition)).decode()
                    with self.assertRaisesRegex(ValueError, 'Invalid transaction'):
                        control_refresh.validate_transaction(bad, base=f.f.base)
        self.assertEqual(f.restore()['status'], 'restored_artifacts_retained')
        journal_raw = (f.f.base / refresh.JOURNAL).read_bytes()
        self.assertGreater(len(journal_raw), len(f.refresh_raw))
        journal = json.loads(journal_raw)['payload']
        self.assertEqual(journal['receipt'], receipt)
        self.assertEqual(journal['return_proof'], proof)
        self.assertEqual(f.c.transaction_path.read_bytes(), f.original_transaction)
        for name, record in f.original_wrappers.items():
            self.assertEqual(original.snapshot(f.f.base / name), record)
        f.assert_artifacts_unchanged()
        print('CAPACITY_BYTES', dict(root=len(f.root_raw), original_transaction=len(f.original_transaction),
              candidate=f.native_path.stat().st_size, refresh=len(f.refresh_raw), journal=len(journal_raw)))

    def test_fixed_caps_refuse_before_writes_and_after_reader(self):
        cap = 64 * 1024 * 1024
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            path = base / control_refresh.RECEIPT
            with path.open('wb') as stream:
                stream.truncate(cap + 1)
            path.chmod(0o444)
            for reader in (refresh.raw, refresh.snapshot, original.bounded_json,
                           lambda p: original.bounded_json(p, max_bytes=cap)):
                with self.assertRaisesRegex(Exception, 'Oversized'):
                    reader(path)
            with self.assertRaisesRegex(Exception, 'Oversized'):
                control_refresh.load(base, 'a' * 64, base / 'restart_production.py')
            # A supplied observation reader must not evade the post-read bound.
            path.chmod(0o600)
            path.write_bytes(b'{}')
            path.chmod(0o444)
            oversized = b'x' * (cap + 1)
            with self.assertRaisesRegex(Exception, 'Oversized'):
                control_refresh.load(base, 'a' * 64, base / 'restart_production.py', read=lambda _: oversized)
            target = base / 'unpublished'
            with patch.object(refresh, 'atomic_write') as writes, patch.object(refresh.tempfile, 'mkstemp') as temps:
                with self.assertRaisesRegex(Exception, 'large|Oversized'):
                    refresh.journal(base, {'padding': 'x' * cap}, 'prepared')
                with self.assertRaisesRegex(Exception, 'large|Oversized'):
                    refresh.sealed_write(target, oversized)
                writes.assert_not_called()
                temps.assert_not_called()
            self.assertFalse(target.exists())
            self.assertFalse((base / refresh.JOURNAL).exists())
