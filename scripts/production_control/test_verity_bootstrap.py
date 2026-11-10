"""Isolated runtime staging tests; no signed app or production service mutation."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

import production_launcher as launcher
import release_build
import verity_bootstrap as bootstrap


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.donor = self.root / 'donor-release'
        self.donor_runtime = self.donor / 'runtime'
        self.manifest = self.donor / 'release.json'
        self.output = self.root / 'bootstrap-runtime'
        source = os.environ.get('VERITY_BOOTSTRAP_TEST_PYTHON')
        if not source:
            self.skipTest('Set VERITY_BOOTSTRAP_TEST_PYTHON to a standalone runtime venv python')
        self.source_python = Path(source).absolute()
        self.source_root = self.source_python.parents[2]

    def build_donor(self):
        self.donor.mkdir()
        release_build.private_python(self.source_python, self.donor_runtime,
                                     source_root=self.source_root)
        release_build.seal(self.donor_runtime)
        descriptor = {'root': str(self.donor_runtime), 'inventory': launcher.inventory(self.donor_runtime)}
        manifest = {
            'schema_version': 2,
            'release_id': self.donor.name,
            'services': {'agent': {'runtimes': [descriptor]}},
        }
        self.manifest.write_bytes(bootstrap.encoded(manifest))
        return manifest

    def test_staged_runtime_starts_after_donor_disappears(self):
        manifest = self.build_donor()
        result = bootstrap.stage(self.manifest, self.output)
        self.assertEqual(result['source']['release_id'], 'donor-release')
        self.assertEqual(result['source']['manifest_sha256'], bootstrap.digest(self.manifest.read_bytes()))
        self.assertEqual(result['payload']['python'], str(self.output / 'venv/bin/python'))
        for base in (self.output / 'python', self.output / 'venv'):
            for directory, _, files in os.walk(base, followlinks=False):
                for name in files:
                    path = Path(directory) / name
                    if path.is_symlink():
                        self.assertTrue(path.resolve().is_relative_to(self.output), str(path))
        self.donor.rename(self.root / 'donor-is-gone')
        self.assertFalse(self.donor.exists())
        verified = bootstrap.verify(self.output)
        self.assertEqual(verified['payload']['python'], str(self.output / 'venv/bin/python'))

    def test_changed_donor_inventory_never_creates_output(self):
        self.build_donor()
        target = next(path for path in (self.donor_runtime / 'python/lib').rglob('*.py'))
        current_mode = target.stat().st_mode
        target.chmod(current_mode | 0o200)
        target.write_text(target.read_text() + '\n# donor drift\n')
        with self.assertRaisesRegex(RuntimeError, 'approved inventory'):
            bootstrap.stage(self.manifest, self.output)
        self.assertFalse(self.output.exists())

    def test_payload_drift_fails_verification(self):
        self.build_donor()
        bootstrap.stage(self.manifest, self.output)
        target = next(path for path in (self.output / 'python/lib').rglob('*.py'))
        target.chmod(target.stat().st_mode | 0o200)
        target.write_text(target.read_text() + '\n# staged drift\n')
        with self.assertRaisesRegex(RuntimeError, 'approved inventory'):
            bootstrap.verify(self.output)


if __name__ == '__main__':
    unittest.main()
