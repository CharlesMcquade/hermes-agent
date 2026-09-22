"""Migration fault boundaries; never invokes launchctl."""
import json
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import install_controls as installer
from production_launcher import inventory


class Interrupted(BaseException):
    pass


class InstallTests(unittest.TestCase):
    def fixture(self, root):
        base = root / 'maintenance'
        base.mkdir()
        (base / 'production_launcher.py').write_text('def main(): print("legacy-check")\n')
        (base / 'production-release.json').write_text('{"schema_version":1}')
        (base / 'webui-watchdog.sh').write_text('#!/bin/sh\nexit 0\n')
        state = root / 'state'
        (state / 'webui').mkdir(parents=True)
        manifest = {'schema_version': 2, 'state_dir': str(state), 'services': {}}
        for name in ('agent', 'webui'):
            repo = root / name
            repo.mkdir()
            (repo / 'main.py').write_text('print("approved")\n')
            plist = root / (name + '.plist')
            plist.write_bytes(plistlib.dumps({'Label': name}))
            manifest['services'][name] = {'repo': str(repo), 'cwd': str(repo),
                'argv': [sys.executable, str(repo / 'main.py')], 'inventory': inventory(repo),
                'plist_path': str(plist), 'commit': 'fixture'}
        baseline = root / 'baseline.json'
        baseline.write_text(json.dumps(manifest))
        return base, baseline

    def test_normal_install_and_each_publication_boundary_keep_valid_launcher(self):
        for boundary in (None, 'production_launcher.py', 'restart_production.py',
                         'approved_restart_job.py', 'production-release.json', 'webui-watchdog.sh'):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as directory:
                base, baseline = self.fixture(Path(directory))
                write = installer.atomic_write
                save = installer.save_json
                def crash_write(path, content):
                    write(path, content)
                    if Path(path).name == boundary:
                        raise Interrupted()
                def crash_save(path, content):
                    save(path, content)
                    if Path(path).name == boundary:
                        raise Interrupted()
                with patch.object(installer, 'atomic_write', side_effect=crash_write), patch.object(installer, 'save_json', side_effect=crash_save):
                    if boundary:
                        with self.assertRaises(Interrupted):
                            installer.install(base, baseline, 'fixture')
                    else:
                        result = installer.install(base, baseline, 'fixture')
                        self.assertEqual(result['status'], 'installed_not_restarted')
                check = subprocess.run([sys.executable, '-B', str(base / 'production_launcher.py'), 'webui', '--check'],
                                       capture_output=True, text=True)
                self.assertEqual(check.returncode, 0, check.stderr)
                schema = json.loads((base / 'production-release.json').read_text())['schema_version']
                self.assertIn('legacy-check' if schema == 1 else 'production runtime OK', check.stdout)


if __name__ == '__main__':
    unittest.main()
