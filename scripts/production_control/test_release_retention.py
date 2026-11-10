"""Tests for N-1, dependency-aware, restorable release retention."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import release_retention as retention


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ReleaseRetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.releases = self.root / 'releases'
        self.releases.mkdir()
        for name in ('old', 'previous', 'current', 'boot-anchor'):
            tree = self.releases / name
            tree.mkdir()
            (tree / 'payload').write_text(name)
            (tree / 'release.json').write_text(json.dumps({'release_id': name, 'services': {}}))
        self.current = self.releases / 'current/release.json'
        manifest = json.loads(self.current.read_text())
        manifest['baseline_sha256'] = sha(self.releases / 'previous/release.json')
        self.current.write_text(json.dumps(manifest))
        self.live = {
            'native-receipt': str(self.releases / 'boot-anchor/runtime/venv/bin/python'),
            'processes': 'host ' + str(self.releases / 'current/runtime/venv/bin/python'),
        }

    def test_collects_native_bootstrap_and_refresh_provenance(self):
        home = self.root / 'home'
        maintenance = home / '.hermes/maintenance'
        maintenance.mkdir(parents=True)
        (home / 'Library/LaunchAgents').mkdir(parents=True)
        settings = (home / 'Applications/Verity.app/Contents/Resources'
                    / 'service-settings.json')
        settings.parent.mkdir(parents=True)
        bootstrap = self.releases / 'boot-anchor/runtime/venv/bin/python'
        settings.write_text(json.dumps({'bootstrap_python': str(bootstrap)}))
        provenance = self.root / 'verity-production-stage-v1'
        (maintenance / 'native-control-refresh-receipt.json').write_text(
            json.dumps({'stage': {'original_stage': str(provenance)}}))
        with mock.patch.object(retention.subprocess, 'check_output', return_value=''):
            texts = retention.collect_live_texts(home)
        self.assertIn(str(bootstrap), texts.get('native-app/service-settings.json', ''))
        self.assertIn(str(provenance),
                      texts.get('maintenance/native-control-refresh-receipt.json', ''))
        plan = retention.retention_plan(self.releases, self.current, texts)
        self.assertIn('boot-anchor', {item['release_id'] for item in plan['keep']})

    def test_plan_keeps_current_previous_and_live_anchor(self):
        plan = retention.retention_plan(self.releases, self.current, self.live)
        self.assertEqual({item['release_id'] for item in plan['keep']}, {'current', 'previous', 'boot-anchor'})
        self.assertEqual([item['release_id'] for item in plan['archive']], ['old'])

    def test_previous_may_live_outside_releases_root(self):
        outside = self.root / 'run-output/previous'
        outside.parent.mkdir()
        (self.releases / 'previous').rename(outside)
        selected = json.loads(self.current.read_text())
        selected['baseline_sha256'] = sha(outside / 'release.json')
        selected['runtime'] = {'source': str(outside / 'runtime/venv/bin/python')}
        self.current.write_text(json.dumps(selected))
        plan = retention.retention_plan(self.releases, self.current, self.live)
        self.assertEqual(plan['retained_outside_releases_root'],
                         [{'path': str(outside), 'reasons': ['N-1']}])
        self.assertEqual([item['release_id'] for item in plan['archive']], ['old'])

    def test_missing_previous_manifest_fails_closed(self):
        previous = json.loads(self.current.read_text())
        previous['baseline_sha256'] = '0' * 64
        self.current.write_text(json.dumps(previous))
        with self.assertRaisesRegex(RuntimeError, 'N-1'):
            retention.retention_plan(self.releases, self.current, self.live)

    def test_apply_verifies_bytes_and_restores_layout(self):
        plan = retention.retention_plan(self.releases, self.current, self.live)
        before = retention.tree_digest(self.releases / 'old')
        selected_before = sha(self.current)
        receipt = retention.apply_plan(plan, self.root / 'trash', self.root / 'receipt.json')
        self.assertFalse((self.releases / 'old').exists())
        archived = self.root / 'trash/old'
        self.assertTrue(archived.is_dir())
        self.assertEqual(retention.tree_digest(archived), before)
        self.assertEqual(sha(self.current), selected_before)
        self.assertEqual(receipt['status'], 'archived')
        self.assertEqual(json.loads((self.root / 'receipt.json').read_text())['moved'], ['old'])

    def test_post_move_verification_failure_restores_original(self):
        plan = retention.retention_plan(self.releases, self.current, self.live)
        expected = plan['archive'][0]['tree_sha256']
        with mock.patch.object(retention, 'tree_digest', side_effect=[expected, 'mismatch']):
            with self.assertRaisesRegex(RuntimeError, 'Archived byte verification failed'):
                retention.apply_plan(plan, self.root / 'trash', self.root / 'receipt.json')
        self.assertTrue((self.releases / 'old').is_dir())
        self.assertFalse((self.root / 'trash/old').exists())

    def test_refused_rename_restores_original_mode(self):
        plan = retention.retention_plan(self.releases, self.current, self.live)
        old = self.releases / 'old'
        old.chmod(0o500)
        with mock.patch.object(retention.os, 'rename', side_effect=PermissionError('refused')):
            with self.assertRaisesRegex(PermissionError, 'refused'):
                retention.apply_plan(plan, self.root / 'trash', self.root / 'receipt.json')
        self.assertEqual(old.stat().st_mode & 0o777, 0o500)

    def test_apply_refuses_stale_plan(self):
        plan = retention.retention_plan(self.releases, self.current, self.live)
        (self.releases / 'old/payload').write_text('changed')
        with self.assertRaisesRegex(RuntimeError, 'changed since'):
            retention.apply_plan(plan, self.root / 'trash', self.root / 'receipt.json')


if __name__ == '__main__':
    unittest.main()
