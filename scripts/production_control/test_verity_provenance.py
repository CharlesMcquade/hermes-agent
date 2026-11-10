"""Durable original-stage migration fixtures; no production admission or services."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import upgrade_native_controls as controls


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name) / 'maintenance'
        self.base.mkdir()
        self.original = self.base / 'original-experiment'
        self.original.mkdir()
        self.output = self.base / 'boot-provenance-v1'
        report_bytes = controls.encoded({'candidate_sha256': 'placeholder'})
        candidate = controls.encoded({'native_host': {'bundle': 'fixture'}})
        report = json.loads(report_bytes)
        report['candidate_sha256'] = controls.sha(candidate)
        report_bytes = controls.encoded(report)
        controls.atomic(self.original / 'stage-report.json', controls.packed(report_bytes))
        controls.atomic(self.original / 'candidate-release.json', controls.packed(candidate))
        self.root = {'report': report}
        self.receipt = {'stage': {
            'base': str(self.base),
            'original_stage': str(self.original),
            'original_stage_sha256': controls.sha(report_bytes),
            'version': str(self.base / 'control-refresh-versions/old'),
        }}
        raw_receipt = controls.encoded(self.receipt)
        self.pin = controls.sha(raw_receipt)
        controls.atomic(self.base / controls.RECEIPT, controls.packed(raw_receipt))
        controls.atomic(self.base / 'native-install-receipt.json',
                        controls.packed(controls.encoded({'receipt': self.root})))
        controls.atomic(self.base / 'control.lock', controls.packed(b'', 0o600))

    def test_original_records_survive_move_out_of_experiment_tree(self):
        with patch.object(controls, 'admit', return_value=None):
            result = controls.stage_durable_provenance(self.base, self.output, self.pin)
        self.assertEqual(result['original_stage'], str(self.output))
        migrated = json.loads(json.dumps(self.receipt))
        migrated['stage']['original_stage'] = str(self.output)
        self.original.rename(self.base / 'experiment-removed')
        self.assertEqual(controls.verify_durable_provenance(migrated, self.root, self.output),
                         self.output)
        for name in ('stage-report.json', 'candidate-release.json'):
            self.assertEqual((self.output / name).read_bytes(),
                             (self.base / 'experiment-removed' / name).read_bytes())

    def test_changed_durable_record_fails_validation(self):
        with patch.object(controls, 'admit', return_value=None):
            controls.stage_durable_provenance(self.base, self.output, self.pin)
        target = self.output / 'candidate-release.json'
        target.chmod(0o600)
        target.write_bytes(target.read_bytes() + b'\n')
        migrated = json.loads(json.dumps(self.receipt))
        migrated['stage']['original_stage'] = str(self.output)
        with self.assertRaisesRegex(ValueError, 'digest mismatch|differs'):
            controls.verify_durable_provenance(migrated, self.root, self.output)


if __name__ == '__main__':
    unittest.main()
