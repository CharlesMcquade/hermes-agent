"""Offline runtime preservation and source-environment regression tests."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import release_build as builder


class BuilderTests(unittest.TestCase):
    def test_symlink_virtualenv_metadata_comes_from_requested_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            subprocess.run([sys.executable, '-m', 'venv', '--without-pip', str(source)], check=True)
            python = source / 'bin/python'
            site = Path(subprocess.check_output([str(python), '-c',
                'import sysconfig;print(sysconfig.get_paths()["purelib"])'], text=True).strip())
            (site / 'release_sentinel.py').write_text('VERSION="selected-venv"\n')
            # Inspect the actual environment query; intercept only the expensive
            # distribution copy after query succeeds. No synthetic query result.
            def copy(src, dest, **kwargs):
                if dest == root / 'private/python':
                    return
                if dest.name == 'site-packages':
                    self.assertEqual(Path(src), site)
                    raise RuntimeError('verified-source-copy')
            real_run = builder.run
            def run(argv, **kwargs):
                if argv[0] == str(python):
                    return real_run(argv, **kwargs)
                if '-m' in argv:
                    return ''
                return str(root / 'private/venv/site-packages')
            with patch.object(builder.shutil, 'copytree', side_effect=copy), patch.object(builder, 'run', side_effect=run):
                with self.assertRaisesRegex(RuntimeError, 'verified-source-copy'):
                    builder.private_python(python.absolute(), root / 'private')
            self.assertEqual(subprocess.check_output([str(python), '-c',
                'import release_sentinel;print(release_sentinel.VERSION)'], text=True).strip(), 'selected-venv')


if __name__ == '__main__':
    unittest.main()
