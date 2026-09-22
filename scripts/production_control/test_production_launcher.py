"""Hermetic launch tests: no live Hermes state, GitHub, or launchd."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import production_launcher as launcher


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'development'
        self.source.mkdir()
        self.release = self.root / 'release'
        self.release.mkdir()
        (self.source / 'server.py').write_text('print("approved")\n')
        (self.release / 'server.py').write_text('print("approved")\n')
        self.item = {'repo': str(self.release), 'cwd': str(self.release),
                     'argv': [sys.executable, str(self.release / 'server.py')],
                     'commit': 'a' * 40, 'version': 'fixture', 'env': {},
                     'inventory': launcher.inventory(self.release), 'requires': []}
        self.services = {'agent': self.item, 'webui': dict(self.item, requires=['agent'])}

    def test_development_commits_and_notes_do_not_block_frozen_release(self):
        (self.source / 'server.py').write_text('print("unapproved change")\n')
        (self.source / 'NOTES.txt').write_text('notes')
        self.assertEqual(launcher.validate('webui', self.services), self.services['webui'])
        result = subprocess.run(launcher.launch_command(self.item), cwd=self.release,
                                env=launcher.launch_environment(self.item), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'approved')

    def test_modified_or_shadowing_release_code_is_rejected(self):
        (self.release / 'server.py').write_text('print("tampered")\n')
        with self.assertRaisesRegex(RuntimeError, 'content'):
            launcher.validate('webui', self.services)
        (self.release / 'server.py').write_text('print("approved")\n')
        (self.release / 'json.py').write_text('raise RuntimeError("shadow")\n')
        with self.assertRaisesRegex(RuntimeError, 'content'):
            launcher.validate('webui', self.services)

    def test_metadata_is_not_authority_and_unapproved_bytecode_is_rejected(self):
        (self.release / '.git').mkdir()
        (self.release / '.git' / 'HEAD').write_text('metadata')
        launcher.validate('webui', self.services)
        (self.release / '__pycache__').mkdir()
        (self.release / '__pycache__' / 'server.pyc').write_bytes(b'cache')
        with self.assertRaisesRegex(RuntimeError, 'content'):
            launcher.validate('webui', self.services)

    def test_missing_executable_and_dependency_cycle_fail_preflight(self):
        self.item['argv'][0] = str(self.root / 'missing-python')
        with self.assertRaisesRegex(RuntimeError, 'executable'):
            launcher.validate('agent', self.services)
        self.item['argv'][0] = sys.executable
        self.item['requires'] = ['webui']
        with self.assertRaisesRegex(RuntimeError, 'Circular'):
            launcher.validate('agent', self.services)

    def test_symlink_escape_is_rejected(self):
        (self.release / 'outside.py').symlink_to(self.source / 'server.py')
        with self.assertRaisesRegex(RuntimeError, 'symlink'):
            launcher.inventory(self.release)

    def test_launcher_does_not_need_git_or_network(self):
        manifest = self.root / 'production-release.json'
        manifest.write_text(json.dumps({'schema_version': 2, 'services': self.services}))
        result = subprocess.run([sys.executable, str(Path(launcher.__file__)), 'webui',
                                 '--manifest', str(manifest), '--check'],
                                env={'PATH': '/nonexistent', 'HOME': str(self.root)},
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_mutable_cwd_cannot_shadow_runtime_or_startup(self):
        marker = self.root / 'shadow-executed'
        poison = f'from pathlib import Path; Path({str(marker)!r}).write_text("bad"); raise RuntimeError("shadow")\n'
        for name in ('json.py', 'sitecustomize.py', 'hermes_cli.py'):
            (self.source / name).write_text(poison)
        (self.release / 'hermes_cli.py').write_text('import json; print("approved")\n')
        self.item.update(cwd=str(self.source), env={'PYTHONPATH': str(self.release)},
                         argv=[sys.executable, '-m', 'hermes_cli'])
        result = subprocess.run(launcher.launch_command(self.item), cwd=self.source,
                                env=launcher.launch_environment(self.item), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'approved')
        self.assertFalse(marker.exists())

    def test_launch_rejects_revoked_and_malformed_policy(self):
        manifest = self.root / 'release.json'
        manifest.write_text(json.dumps({'schema_version': 2, 'release_id': 'bad', 'services': self.services}))
        policy = self.root / 'revoked-releases.json'
        policy.write_text(json.dumps({'schema_version': 1, 'release_ids': ['bad'], 'content_digests': []}))
        with self.assertRaisesRegex(RuntimeError, 'revoked'):
            launcher.load_manifest(manifest)
        policy.write_text('{}')
        with self.assertRaisesRegex(RuntimeError, 'Malformed'):
            launcher.load_manifest(manifest)

    def test_runtime_environment_cannot_redirect_source(self):
        self.item['env'] = {'PYTHONPATH': str(self.release)}
        old = os.environ.get('PYTHONPATH')
        os.environ['PYTHONPATH'] = str(self.source)
        try:
            self.assertEqual(launcher.launch_environment(self.item)['PYTHONPATH'], str(self.release))
        finally:
            if old is None:
                os.environ.pop('PYTHONPATH', None)
            else:
                os.environ['PYTHONPATH'] = old


if __name__ == '__main__':
    unittest.main()
